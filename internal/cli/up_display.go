package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/termui"
	"github.com/koltyakov/expose/internal/traffic"
)

const (
	upANSIReset     = termui.Reset
	upANSIBold      = termui.Bold
	upANSIDim       = termui.Dim
	upANSIRed       = termui.Red
	upANSIGreen     = termui.Green
	upANSIYellow    = termui.Yellow
	upANSICyan      = termui.Cyan
	upANSIHome      = termui.Home
	upANSIClearDown = termui.ClearDown
	upANSIHideCur   = termui.HideCur
	upANSIShowCur   = termui.ShowCur
)

const (
	upDisplayFieldWidth   = 19
	upDisplayContentWidth = 78
	upMaxDisplayReqs      = 10
	upActiveClientWindow  = 60 * time.Second
	upWSCloseDebounce     = 500 * time.Millisecond
	upMicroDisconnectMax  = 5 * time.Second
	upLocalHealthCacheTTL = 2 * time.Second
	upLocalHealthTimeout  = 200 * time.Millisecond
	upLatencySampleMax    = 1024
)

type upDashboard struct {
	mu                sync.Mutex
	out               io.Writer
	color             bool
	terminalColumnsFn func() int
	version           string
	configPath        string
	startedAt         time.Time
	protectAll        bool

	order          []string
	groups         map[string]*upDashboardGroup
	events         []upDashboardEvent
	reqs           []upDashboardRequest
	latencySamples []time.Duration

	serverVersions  map[string]string
	tlsModes        map[string]string
	latencies       map[string]string
	wafEnabled      map[string]bool
	wafBlocked      int64
	visitors        map[string]time.Time
	wsConns         map[string]upDashboardWS
	localHealth     map[string]upDashboardLocalHealth
	trafficMeters   map[string]*traffic.Meter
	totalHTTP       int
	wsDisplayMin    int
	wsDebounceTimer *time.Timer
	wsDebounceGen   uint64
	statusText      string
	statusChangedAt time.Time
	noticeText      string
	noticeLevel     string

	pendingDisconnectAt time.Time
	sessionDowntime     time.Duration
	sessionDisconnects  int

	stopCh  chan struct{}
	doneCh  chan struct{}
	nowFunc func() time.Time
}

type upDashboardGroup struct {
	Subdomain     string
	Status        string
	PublicURL     string
	TunnelID      string
	LastMessage   string
	LastUpdatedAt time.Time
	Requests      int
	LastReqMethod string
	LastReqPath   string
	LastReqStatus int
	Routes        []upLocalRoute
}

type upDashboardWS struct {
	Subdomain   string
	StreamID    string
	Path        string
	Fingerprint string
	OpenedAt    time.Time
}

type upDashboardLocalHealth struct {
	OK        bool
	CheckedAt time.Time
}

type upDashboardEvent struct {
	At        time.Time
	Subdomain string
	Level     string
	Message   string
}

type upDashboardRequest struct {
	At        time.Time
	Subdomain string
	Method    string
	Path      string
	Status    int
	Duration  string
}

func newUpDashboard(configPath, version string) *upDashboard {
	return &upDashboard{
		out:            os.Stdout,
		color:          isInteractiveOutput(),
		version:        version,
		configPath:     configPath,
		startedAt:      time.Now(),
		groups:         make(map[string]*upDashboardGroup),
		serverVersions: make(map[string]string),
		tlsModes:       make(map[string]string),
		latencies:      make(map[string]string),
		wafEnabled:     make(map[string]bool),
		visitors:       make(map[string]time.Time),
		wsConns:        make(map[string]upDashboardWS),
		localHealth:    make(map[string]upDashboardLocalHealth),
		trafficMeters:  make(map[string]*traffic.Meter),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
		nowFunc:        time.Now,
	}
}

func (d *upDashboard) InitGroups(order []string, hostRoutes map[string][]upLocalRoute, protectAll bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.order = append([]string(nil), order...)
	d.protectAll = protectAll
	for _, sub := range d.order {
		routes := append([]upLocalRoute(nil), hostRoutes[sub]...)
		d.groups[sub] = &upDashboardGroup{
			Subdomain:     sub,
			Status:        "starting",
			LastMessage:   "initializing",
			LastUpdatedAt: d.now(),
			Routes:        routes,
		}
	}
}

func (d *upDashboard) Start(ctx context.Context) {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.color {
		_, _ = fmt.Fprint(d.out, upANSIHideCur)
	}
	d.redrawLocked()
	d.mu.Unlock()

	go func() {
		defer close(d.doneCh)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.mu.Lock()
				d.redrawLocked()
				d.mu.Unlock()
			}
		}
	}()
}

func (d *upDashboard) Cleanup() {
	if d == nil {
		return
	}
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
	<-d.doneCh

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.color {
		_, _ = fmt.Fprint(d.out, upANSIShowCur)
	}
}

func (d *upDashboard) Logger(subdomain string) *slog.Logger {
	handler := &upDashboardHandler{
		ui:        d,
		subdomain: subdomain,
		level:     slog.LevelInfo,
	}
	return slog.New(handler)
}

func (d *upDashboard) SetGroupStatus(subdomain, status, msg string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.ensureGroupLocked(subdomain)
	g.Status = status
	if strings.TrimSpace(msg) != "" {
		g.LastMessage = strings.TrimSpace(msg)
	}
	g.LastUpdatedAt = d.now()
	d.syncAggregateSessionStateLocked(g.LastUpdatedAt)
	d.redrawLocked()
}

func (d *upDashboard) SetGroupStopped(subdomain string, err error) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.ensureGroupLocked(subdomain)
	if err == nil {
		g.Status = "stopped"
		g.LastMessage = "stopped"
	} else {
		g.Status = "error"
		g.LastMessage = shortenDashboardText(err.Error(), 80)
		d.appendEventLocked(upDashboardEvent{
			At:        d.now(),
			Subdomain: subdomain,
			Level:     "ERROR",
			Message:   shortenDashboardText(err.Error(), 120),
		})
	}
	g.LastUpdatedAt = d.now()
	d.syncAggregateSessionStateLocked(g.LastUpdatedAt)
	d.redrawLocked()
}

func (d *upDashboard) HandleLog(subdomain string, level slog.Level, msg string, attrs []slog.Attr) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	g := d.ensureGroupLocked(subdomain)
	now := d.now()
	attrMap := flattenSlogAttrs(attrs)
	msg = strings.TrimSpace(msg)

	switch msg {
	case "tunnel ready":
		g.Status = "online"
		if v := attrString(attrMap, "public_url"); v != "" {
			g.PublicURL = v
		}
		if v := attrString(attrMap, "tunnel_id"); v != "" {
			g.TunnelID = v
		}
		g.LastMessage = "tunnel ready"
	case "client disconnected; reconnecting":
		g.Status = "reconnecting"
		g.LastMessage = msg
	case "tunnel register failed", "tunnel register failed while waiting for TLS certificate provisioning":
		if g.Status != "reconnecting" {
			g.Status = "connecting"
		}
		g.LastMessage = msg
	case "server TLS certificate provisioning in progress; retrying":
		if g.Status != "reconnecting" {
			g.Status = "waiting-tls"
		}
		g.LastMessage = "waiting for TLS certificate"
	case "forwarded request":
		g.Requests++
		d.totalHTTP++
		g.LastReqMethod = attrString(attrMap, "method")
		g.LastReqPath = attrString(attrMap, "path")
		g.LastReqStatus = attrInt(attrMap, "status")
		d.touchVisitorLocked(attrString(attrMap, "client_fingerprint"))
		d.appendRequestLocked(upDashboardRequest{
			At:        now,
			Subdomain: subdomain,
			Method:    g.LastReqMethod,
			Path:      g.LastReqPath,
			Status:    g.LastReqStatus,
			Duration:  attrString(attrMap, "duration"),
		})
	case "versions":
		if v := attrString(attrMap, "server"); v != "" {
			d.serverVersions[subdomain] = v
		}
		if attrBool(attrMap, "waf_enabled") {
			d.wafEnabled[subdomain] = true
		}
	case "server tls mode":
		if v := attrString(attrMap, "mode"); v != "" {
			d.tlsModes[subdomain] = v
		}
	case "latency":
		if v := dashboardFormatRequestDuration(attrString(attrMap, "duration")); strings.TrimSpace(v) != "" {
			d.latencies[subdomain] = v
		}
	case "waf stats":
		blocked := attrInt64(attrMap, "blocked")
		if blocked > d.wafBlocked {
			d.wafBlocked = blocked
		}
	case "forwarded websocket opened":
		streamID := attrString(attrMap, "stream_id")
		if streamID != "" {
			fp := attrString(attrMap, "client_fingerprint")
			d.touchVisitorLocked(fp)
			d.wsConns[subdomain+"|"+streamID] = upDashboardWS{
				Subdomain:   subdomain,
				StreamID:    streamID,
				Path:        attrString(attrMap, "path"),
				Fingerprint: fp,
				OpenedAt:    now,
			}
		}
	case "forwarded websocket closed":
		streamID := attrString(attrMap, "stream_id")
		if streamID != "" {
			d.trackWSCloseLocked(subdomain + "|" + streamID)
		}
	default:
		if level >= slog.LevelError {
			g.Status = "error"
		}
		if msg != "" {
			g.LastMessage = shortenDashboardText(msg, 80)
		}
	}
	g.LastUpdatedAt = now

	if msg != "forwarded request" &&
		msg != "versions" &&
		msg != "server tls mode" &&
		msg != "latency" &&
		msg != "waf stats" &&
		msg != "forwarded websocket opened" &&
		msg != "forwarded websocket closed" {
		summary := summarizeDashboardEvent(msg, attrMap)
		d.appendEventLocked(upDashboardEvent{
			At:        now,
			Subdomain: subdomain,
			Level:     dashboardLevelLabel(level),
			Message:   summary,
		})
		if summary != "" {
			d.setNoticeLocked(dashboardLevelLabel(level), summary)
		}
	}
	d.syncAggregateSessionStateLocked(now)
	d.redrawLocked()
}

func (d *upDashboard) RecordTraffic(subdomain string, direction traffic.Direction, bytes int64) {
	if d == nil || bytes <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trafficMeterLocked(subdomain).AddAt(d.now(), direction, bytes)
}

func (d *upDashboard) ensureGroupLocked(subdomain string) *upDashboardGroup {
	if d.groups == nil {
		d.groups = make(map[string]*upDashboardGroup)
	}
	if g, ok := d.groups[subdomain]; ok {
		return g
	}
	g := &upDashboardGroup{
		Subdomain:     subdomain,
		Status:        "starting",
		LastUpdatedAt: d.now(),
	}
	d.groups[subdomain] = g
	d.order = append(d.order, subdomain)
	return g
}

func (d *upDashboard) appendEventLocked(ev upDashboardEvent) {
	d.events = append(d.events, ev)
	const maxEvents = 8
	if len(d.events) > maxEvents {
		copy(d.events, d.events[len(d.events)-maxEvents:])
		d.events = d.events[:maxEvents]
	}
}

func (d *upDashboard) appendRequestLocked(req upDashboardRequest) {
	d.reqs = append(d.reqs, req)
	if len(d.reqs) > upMaxDisplayReqs {
		copy(d.reqs, d.reqs[len(d.reqs)-upMaxDisplayReqs:])
		d.reqs = d.reqs[:upMaxDisplayReqs]
	}
	if parsed, ok := dashboardParseRequestDuration(req.Duration); ok {
		d.appendLatencySampleLocked(parsed)
	}
}

func (d *upDashboard) appendLatencySampleLocked(v time.Duration) {
	if v < 0 {
		v = 0
	}
	d.latencySamples = append(d.latencySamples, v)
	if len(d.latencySamples) > upLatencySampleMax {
		copy(d.latencySamples, d.latencySamples[len(d.latencySamples)-upLatencySampleMax:])
		d.latencySamples = d.latencySamples[:upLatencySampleMax]
	}
}

func (d *upDashboard) syncAggregateSessionStateLocked(now time.Time) {
	status := d.aggregateStatusLocked()
	prevStatus := d.statusText
	if prevStatus == "reconnecting" && status != "reconnecting" {
		d.finalizePendingDisconnectLocked(now)
	}
	if prevStatus != "reconnecting" && status == "reconnecting" {
		d.pendingDisconnectAt = now
	}
	if status == "" {
		d.statusText = ""
		d.statusChangedAt = time.Time{}
		d.pendingDisconnectAt = time.Time{}
		return
	}
	if prevStatus != status || d.statusChangedAt.IsZero() {
		d.statusChangedAt = now
	}
	d.statusText = status
	if status == "online" {
		d.noticeText = ""
		d.noticeLevel = ""
	}
}

func (d *upDashboard) finalizePendingDisconnectLocked(now time.Time) {
	if d.pendingDisconnectAt.IsZero() {
		return
	}
	downtime := now.Sub(d.pendingDisconnectAt)
	if downtime >= upMicroDisconnectMax {
		d.sessionDowntime += downtime
		d.sessionDisconnects++
	}
	d.pendingDisconnectAt = time.Time{}
}

func (d *upDashboard) setNoticeLocked(level, msg string) {
	msg = strings.TrimSpace(msg)
	level = strings.ToLower(strings.TrimSpace(level))
	d.noticeText = msg
	d.noticeLevel = level
}

func (d *upDashboard) redrawLocked() {
	var b strings.Builder
	renderNow := d.now()
	if d.color {
		b.WriteString(upANSIHome)
		b.WriteString(upANSIClearDown)
	}

	b.WriteString("\n")
	name := d.styled(upANSIBold+upANSICyan, "expose")
	if strings.TrimSpace(d.version) != "" {
		name += " " + d.styled(upANSIDim, d.version)
	}
	hint := d.styled(upANSIDim, "(Ctrl+C to quit)")
	visHint := len("(Ctrl+C to quit)")
	visName := len("expose")
	if d.version != "" {
		visName += 1 + len(d.version)
	}
	gap := max(upDisplayContentWidth-visName-visHint, 4)
	fmt.Fprintf(&b, "%s%s%s\n\n", name, strings.Repeat(" ", gap), hint)

	placeholder := d.styled(upANSIDim, "--")
	trafficSnapshot := d.aggregateTrafficSnapshotLocked()
	tunnelIDs := d.tunnelIDsLocked()
	d.syncAggregateSessionStateLocked(renderNow)
	status := d.statusText
	if status != "" {
		statusColor := upANSIGreen
		if status != "online" {
			statusColor = upANSIYellow
		}
		statusValue := d.styled(statusColor, status)
		if !d.statusChangedAt.IsZero() {
			statusValue += d.styled(upANSIDim, " for ")
			statusValue += upFormatHeaderUptime(renderNow.Sub(d.statusChangedAt))
		}
		if tunnelIDs != "" {
			statusValue += d.styled(upANSIDim, " (ID: "+tunnelIDs+")")
		}
		d.writeField(&b, "Session", statusValue)
	} else {
		statusValue := placeholder
		if tunnelIDs != "" {
			statusValue += d.styled(upANSIDim, " (ID: "+tunnelIDs+")")
		}
		d.writeField(&b, "Session", statusValue)
	}
	if details := d.sessionStatsDetailLocked(renderNow); details != "" {
		d.writeFieldContinuation(&b, details)
	}
	if d.noticeText != "" && status == "reconnecting" {
		d.writeField(&b, "", d.noticeDisplayTextLocked())
	}

	serverVersion := d.serverVersionDisplayLocked()
	tlsMode := d.joinMapValuesLocked(d.tlsModes)
	if serverVersion == "" {
		serverVersion = "--"
	}
	serverVersionValue := d.styled(upANSIDim, serverVersion)
	if serverVersion != "--" {
		serverVersionValue = serverVersion // default terminal color (white in dark themes)
	}
	meta := make([]string, 0, 2)
	if d.anyWAFEnabledLocked() {
		meta = append(meta, "WAF: On")
	}
	if tlsMode != "" {
		meta = append(meta, "TLS: "+upCapitalizeCSV(tlsMode))
	}
	if len(meta) > 0 {
		serverVersionValue += d.styled(upANSIDim, " ("+strings.Join(meta, ", ")+")")
	}
	if serverVersion != "" {
		d.writeField(&b, "Server", serverVersionValue)
	} else {
		d.writeField(&b, "Server", placeholder)
	}
	latency := d.joinMapValuesLocked(d.latencies)
	if latency != "" {
		d.writeField(&b, "Latency", latency)
	} else {
		d.writeField(&b, "Latency", placeholder)
	}

	forwardings := d.forwardingLinesLocked()
	if len(forwardings) == 0 {
		d.writeField(&b, "Forwarding", placeholder)
	} else {
		for i, line := range forwardings {
			if i == 0 {
				d.writeField(&b, "Forwarding", line)
				continue
			}
			d.writeFieldContinuation(&b, line)
		}
	}
	if d.noticeText != "" && status != "reconnecting" {
		d.writeField(&b, "", d.noticeDisplayTextLocked())
	}

	wsCount := max(d.wsDisplayMin, len(d.wsConns))
	activeCount := d.activeClientCountLocked()
	clientCount := len(d.visitors)
	d.writeField(&b, "Traffic", d.trafficSummaryText(trafficSnapshot))
	d.writeField(&b, "Clients", fmt.Sprintf("%d active, %d total", activeCount, clientCount))
	if wsCount > 0 {
		d.writeField(&b, "WebSockets", fmt.Sprintf("%d open", wsCount))
	} else {
		d.writeField(&b, "WebSockets", placeholder)
	}

	b.WriteString("\n")
	httpSummary := fmt.Sprintf("%d total", d.totalHTTP)
	if d.anyWAFEnabledLocked() {
		if d.wafBlocked > 0 {
			httpSummary += ", " + d.styled(upANSIRed, fmt.Sprintf("blocked %d", d.wafBlocked))
		} else {
			httpSummary += ", blocked 0"
		}
	}
	b.WriteString(d.styled(upANSIBold, "HTTP Requests    "))
	b.WriteString("  ")
	b.WriteString(d.styled(upANSIDim, httpSummary))
	b.WriteString("\n")
	b.WriteString(d.styled(upANSIDim, strings.Repeat("─", upDisplayContentWidth)))
	b.WriteString("\n")

	if len(d.reqs) == 0 {
		b.WriteString(d.styled(upANSIDim, "Waiting for requests…"))
		b.WriteString("\n")
	} else {
		for _, r := range d.reqs {
			pathText := d.requestDisplayPathLocked(r)
			switch r.Method {
			case "WARN":
				fmt.Fprintf(&b, "%s  %s  %s\n",
					d.styled(upANSIDim, r.At.Format("15:04:05")),
					d.styled(upANSIYellow, "WARN   "),
					pathText,
				)
			case "INFO":
				fmt.Fprintf(&b, "%s  %s  %s\n",
					d.styled(upANSIDim, r.At.Format("15:04:05")),
					d.styled(upANSICyan, "INFO   "),
					pathText,
				)
			default:
				statusStr := d.formatRequestStatusText(r.Status)
				dur := dashboardFormatRequestDuration(r.Duration)
				if dur == "" {
					dur = "--"
				}
				fmt.Fprintf(&b, "%s  %s  %-40s %s %s\n",
					d.styled(upANSIDim, r.At.Format("15:04:05")),
					d.styled(upANSIBold, fmt.Sprintf("%-7s", strings.ToUpper(strings.TrimSpace(r.Method)))),
					truncateRight(pathText, 40),
					statusStr,
					d.styled(upANSIDim, fmt.Sprintf("%7s", dur)),
				)
			}
		}
	}
	if p, ok := upLatencyPercentiles(d.latencySamples); ok {
		b.WriteString("\n")
		b.WriteString("Latency")
		pad := max(upDisplayFieldWidth-len("Latency"), 1)
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(d.styled(upANSIDim, "P50 "))
		b.WriteString(p.p50)
		b.WriteString(d.styled(upANSIDim, " | "))
		b.WriteString(d.styled(upANSIDim, "P90 "))
		b.WriteString(p.p90)
		b.WriteString(d.styled(upANSIDim, " | "))
		b.WriteString(d.styled(upANSIDim, "P95 "))
		b.WriteString(p.p95)
		b.WriteString(d.styled(upANSIDim, " | "))
		b.WriteString(d.styled(upANSIDim, "P99 "))
		b.WriteString(p.p99)
		b.WriteString("\n")
	}

	_, _ = fmt.Fprint(d.out, b.String())
}

func (d *upDashboard) writeField(b *strings.Builder, label, value string) {
	d.writeFieldLines(b, label, []string{value})
}

func (d *upDashboard) writeFieldContinuation(b *strings.Builder, value string) {
	d.writeField(b, "", value)
}

func (d *upDashboard) writeFieldLines(b *strings.Builder, label string, values []string) {
	termui.WriteFieldLines(b, upDisplayFieldWidth, label, values)
}

func upCapitalizeCSV(s string) string {
	return termui.CapitalizeCSV(s)
}

func (d *upDashboard) aggregateStatusLocked() string {
	if len(d.order) == 0 {
		return ""
	}
	seenOnline := false
	seenConnecting := false
	seenReconnecting := false
	seenStarting := false
	seenStopped := false
	for _, sub := range d.order {
		g := d.groups[sub]
		if g == nil {
			continue
		}
		switch strings.TrimSpace(g.Status) {
		case "error":
			return "error"
		case "stopped":
			seenStopped = true
		case "reconnecting":
			seenReconnecting = true
		case "connecting", "waiting-tls":
			seenConnecting = true
		case "starting":
			seenStarting = true
		case "online":
			seenOnline = true
		}
	}
	switch {
	case seenReconnecting:
		return "reconnecting"
	case seenConnecting:
		return "connecting"
	case seenStarting && !seenOnline:
		return "starting"
	case seenStopped && !seenOnline:
		return "stopped"
	case seenOnline:
		return "online"
	default:
		return "starting"
	}
}

func (d *upDashboard) tunnelIDsLocked() string {
	if len(d.order) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(d.order))
	for _, sub := range d.order {
		g := d.groups[sub]
		if g == nil {
			continue
		}
		id := strings.TrimSpace(g.TunnelID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return strings.Join(ids, ", ")
}

func (d *upDashboard) joinMapValuesLocked(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	values := make([]string, 0, len(m))
	for _, sub := range d.order {
		v := strings.TrimSpace(m[sub])
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	// Include values for dynamically added groups not in d.order.
	if len(values) < len(m) {
		extras := make([]string, 0, len(m)-len(values))
		for _, v := range m {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			extras = append(extras, v)
		}
		sort.Strings(extras)
		values = append(values, extras...)
	}
	return strings.Join(values, ", ")
}

func (d *upDashboard) serverVersionDisplayLocked() string {
	if len(d.serverVersions) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	values := make([]string, 0, len(d.serverVersions))
	appendValue := func(sub string) {
		v := strings.TrimSpace(d.serverVersions[sub])
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	for _, sub := range d.order {
		appendValue(sub)
	}
	for sub := range d.serverVersions {
		appendValue(sub)
	}
	return strings.Join(values, ", ")
}

func (d *upDashboard) anyWAFEnabledLocked() bool {
	for _, enabled := range d.wafEnabled {
		if enabled {
			return true
		}
	}
	return false
}

func (d *upDashboard) forwardingLinesLocked() []string {
	lines := make([]string, 0)
	for _, sub := range d.order {
		g := d.groups[sub]
		if g == nil {
			continue
		}
		for _, r := range g.Routes {
			if strings.TrimSpace(g.PublicURL) == "" {
				lines = append(lines, d.styled(upANSIDim, "--"))
				continue
			}
			external := upRouteExternalURL(g.PublicURL, r)
			local := upRouteLocalTarget(r)
			lines = append(lines, d.forwardingValueLinesLocked(external, local, d.localRouteHealthyLocked(r))...)
		}
	}
	return lines
}

func upRouteExternalURL(base string, r upLocalRoute) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	prefix := strings.TrimSpace(r.PathPrefix)
	if prefix == "" || prefix == "/" {
		return base
	}
	return strings.TrimSuffix(base, "/") + prefix
}

func upRouteLocalTarget(r upLocalRoute) string {
	if strings.TrimSpace(r.StaticDir) != "" {
		return "static:" + filepath.Clean(r.StaticDir)
	}
	target := fmt.Sprintf("http://localhost:%d", r.LocalPort)
	prefix := strings.TrimSpace(r.PathPrefix)
	if prefix == "" || prefix == "/" {
		return target
	}
	if r.StripPrefix {
		return target
	}
	return target + prefix
}

func (d *upDashboard) localRouteHealthyLocked(route upLocalRoute) bool {
	cacheKey, dialAddr, ok := upLocalRouteDialAddr(route)
	if !ok {
		return false
	}
	if d.localHealth == nil {
		d.localHealth = make(map[string]upDashboardLocalHealth)
	}
	now := d.now()
	if e, ok := d.localHealth[cacheKey]; ok && now.Sub(e.CheckedAt) < upLocalHealthCacheTTL {
		return e.OK
	}
	conn, err := net.DialTimeout("tcp", dialAddr, upLocalHealthTimeout)
	healthy := err == nil
	if err == nil {
		_ = conn.Close()
	}
	d.localHealth[cacheKey] = upDashboardLocalHealth{
		OK:        healthy,
		CheckedAt: now,
	}
	return healthy
}

func upLocalRouteDialAddr(route upLocalRoute) (cacheKey string, dialAddr string, ok bool) {
	if route.LocalPort <= 0 {
		return "", "", false
	}
	dialAddr = net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", route.LocalPort))
	return dialAddr, dialAddr, true
}

func (d *upDashboard) requestDisplayPathLocked(r upDashboardRequest) string {
	path := strings.TrimSpace(r.Path)
	if path == "" {
		path = "/"
	}
	groupCount := 0
	for _, sub := range d.order {
		if d.groups[sub] != nil {
			groupCount++
			if groupCount > 1 {
				break
			}
		}
	}
	if groupCount <= 1 || strings.TrimSpace(r.Subdomain) == "" {
		return path
	}
	return r.Subdomain + " " + path
}

func (d *upDashboard) touchVisitorLocked(fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return
	}
	d.visitors[fp] = d.now()
}

func (d *upDashboard) activeClientCountLocked() int {
	now := d.now()
	cutoff := now.Add(-upActiveClientWindow)
	active := make(map[string]struct{}, len(d.visitors)+len(d.wsConns))
	for fp, lastSeen := range d.visitors {
		if lastSeen.After(cutoff) {
			active[fp] = struct{}{}
		}
	}
	for _, ws := range d.wsConns {
		if strings.TrimSpace(ws.Fingerprint) != "" {
			active[ws.Fingerprint] = struct{}{}
		}
	}
	return len(active)
}

func (d *upDashboard) trackWSCloseLocked(key string) {
	preCloseCount := len(d.wsConns)
	delete(d.wsConns, key)
	if preCloseCount > d.wsDisplayMin {
		d.wsDisplayMin = preCloseCount
	}
	if d.wsDebounceTimer != nil {
		d.wsDebounceTimer.Stop()
	}
	d.wsDebounceGen++
	gen := d.wsDebounceGen
	d.wsDebounceTimer = time.AfterFunc(upWSCloseDebounce, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if gen != d.wsDebounceGen {
			return
		}
		d.wsDisplayMin = 0
		d.wsDebounceTimer = nil
		d.redrawLocked()
	})
}

func (d *upDashboard) formatRequestStatusText(code int) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Unknown"
	}
	s := fmt.Sprintf("%-10s", fmt.Sprintf("%d %s", code, text))
	switch {
	case code >= 200 && code < 300:
		return d.styled(upANSIGreen, s)
	case code >= 300 && code < 400:
		return d.styled(upANSICyan, s)
	case code >= 400 && code < 500:
		return d.styled(upANSIYellow, s)
	default:
		return d.styled(upANSIRed, s)
	}
}

func (d *upDashboard) styled(code, text string) string {
	return termui.Styler{Color: d.color}.Style(code, text)
}

func (d *upDashboard) now() time.Time {
	if d != nil && d.nowFunc != nil {
		return d.nowFunc()
	}
	return time.Now()
}

func (d *upDashboard) trafficMeterLocked(subdomain string) *traffic.Meter {
	subdomain = strings.TrimSpace(subdomain)
	if d.trafficMeters == nil {
		d.trafficMeters = make(map[string]*traffic.Meter)
	}
	meter, ok := d.trafficMeters[subdomain]
	if ok {
		return meter
	}
	meter = traffic.NewMeter(traffic.DefaultWindow)
	d.trafficMeters[subdomain] = meter
	return meter
}

func (d *upDashboard) aggregateTrafficSnapshotLocked() traffic.Snapshot {
	if len(d.trafficMeters) == 0 {
		return traffic.Snapshot{}
	}
	now := d.now()
	snapshots := make([]traffic.Snapshot, 0, len(d.trafficMeters))
	for _, meter := range d.trafficMeters {
		snapshots = append(snapshots, meter.SnapshotAt(now))
	}
	return traffic.CombineSnapshots(snapshots...)
}

func (d *upDashboard) trafficSummaryText(snapshot traffic.Snapshot) string {
	return "In " + traffic.FormatBytes(snapshot.InboundTotal) + " total " +
		d.styled(upANSIDim, "("+traffic.FormatRate(snapshot.InboundRate)+")") +
		" " + d.styled(upANSIDim, "|") + " " +
		"Out " + traffic.FormatBytes(snapshot.OutboundTotal) + " total " +
		d.styled(upANSIDim, "("+traffic.FormatRate(snapshot.OutboundRate)+")")
}

type upDashboardHandler struct {
	ui        *upDashboard
	subdomain string
	level     slog.Level
	attrs     []slog.Attr
}

func (h *upDashboardHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *upDashboardHandler) Handle(_ context.Context, rec slog.Record) error {
	if h.ui == nil {
		return nil
	}
	attrs := append([]slog.Attr(nil), h.attrs...)
	rec.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	h.ui.HandleLog(h.subdomain, rec.Level, rec.Message, attrs)
	return nil
}

func (h *upDashboardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &clone
}

func (h *upDashboardHandler) WithGroup(_ string) slog.Handler {
	clone := *h
	return &clone
}

func flattenSlogAttrs(attrs []slog.Attr) map[string]slog.Value {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]slog.Value, len(attrs))
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		out[a.Key] = a.Value
	}
	return out
}

func attrString(m map[string]slog.Value, key string) string {
	if len(m) == 0 {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch v.Kind() {
	case slog.KindString:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(v.String())
	}
}

func attrInt(m map[string]slog.Value, key string) int {
	if len(m) == 0 {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch v.Kind() {
	case slog.KindInt64:
		return int(v.Int64())
	case slog.KindUint64:
		return int(v.Uint64())
	case slog.KindString:
		var n int
		_, _ = fmt.Sscanf(v.String(), "%d", &n)
		return n
	default:
		return 0
	}
}

func attrInt64(m map[string]slog.Value, key string) int64 {
	if len(m) == 0 {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch v.Kind() {
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return int64(v.Uint64())
	case slog.KindString:
		var n int64
		_, _ = fmt.Sscanf(v.String(), "%d", &n)
		return n
	default:
		return 0
	}
}

func attrBool(m map[string]slog.Value, key string) bool {
	if len(m) == 0 {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch v.Kind() {
	case slog.KindBool:
		return v.Bool()
	case slog.KindString:
		s := strings.ToLower(strings.TrimSpace(v.String()))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}

func dashboardLevelLabel(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	default:
		return "INFO"
	}
}

func summarizeDashboardEvent(msg string, attrs map[string]slog.Value) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	switch msg {
	case "tunnel ready":
		if u := attrString(attrs, "public_url"); u != "" {
			return msg + " " + u
		}
	case "client disconnected; reconnecting", "tunnel register failed", "tunnel register failed while waiting for TLS certificate provisioning":
		if e := attrString(attrs, "err"); e != "" {
			return shortenDashboardText(msg+": "+e, 120)
		}
	}
	return shortenDashboardText(msg, 120)
}

func upFormatHeaderUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", days, pluralizeUpUnit(days, "day")))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", hours, pluralizeUpUnit(hours, "hour")))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d %s", minutes, pluralizeUpUnit(minutes, "minute")))
	}
	return strings.Join(parts, ", ")
}

func (d *upDashboard) sessionStatsDetailLocked(now time.Time) string {
	if d.startedAt.IsZero() || d.statusText != "reconnecting" {
		return ""
	}
	parts := make([]string, 0, 3)
	if downtime := d.sessionDisplayedDowntimeLocked(now); downtime > 0 {
		parts = append(parts, "downtime "+displayFormatDowntime(downtime))
	}
	parts = append(parts, fmt.Sprintf("%.1f%% uptime", d.sessionUptimePercentLocked(now)))
	if disconnects := d.sessionDisconnectCountLocked(now); disconnects > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", disconnects, pluralizeUpUnit(disconnects, "disconnect")))
	}
	return strings.Join(parts, ", ")
}

func (d *upDashboard) sessionUptimePercentLocked(now time.Time) float64 {
	if d.startedAt.IsZero() {
		return 0
	}
	elapsed := now.Sub(d.startedAt)
	if elapsed <= 0 {
		return 100
	}
	downtime := min(max(d.sessionEffectiveDowntimeLocked(now), 0), elapsed)
	uptime := elapsed - downtime
	pct := float64(uptime) / float64(elapsed) * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func (d *upDashboard) sessionDisconnectCountLocked(now time.Time) int {
	count := d.sessionDisconnects
	if d.statusText == "reconnecting" && !d.pendingDisconnectAt.IsZero() && now.Sub(d.pendingDisconnectAt) >= upMicroDisconnectMax {
		count++
	}
	return count
}

func (d *upDashboard) sessionEffectiveDowntimeLocked(now time.Time) time.Duration {
	downtime := d.sessionDowntime
	if d.statusText == "reconnecting" && !d.pendingDisconnectAt.IsZero() && now.Sub(d.pendingDisconnectAt) >= upMicroDisconnectMax {
		downtime += now.Sub(d.pendingDisconnectAt)
	}
	return downtime
}

func (d *upDashboard) sessionCurrentDowntimeLocked(now time.Time) time.Duration {
	if d.statusText != "reconnecting" || d.pendingDisconnectAt.IsZero() {
		return 0
	}
	downtime := now.Sub(d.pendingDisconnectAt)
	if downtime < 0 {
		return 0
	}
	return downtime
}

func (d *upDashboard) sessionDisplayedDowntimeLocked(now time.Time) time.Duration {
	return d.sessionDowntime + d.sessionCurrentDowntimeLocked(now)
}

func (d *upDashboard) noticeDisplayTextLocked() string {
	switch d.noticeLevel {
	case "warn":
		return d.styled(upANSIYellow, d.noticeText)
	case "info":
		return d.styled(upANSICyan, d.noticeText)
	case "error":
		return d.styled(upANSIRed, d.noticeText)
	default:
		return d.noticeText
	}
}

func pluralizeUpUnit(n int, singular string) string {
	return termui.Pluralize(n, singular)
}

func displayFormatDowntime(d time.Duration) string {
	return termui.FormatDowntime(d)
}

func dashboardFormatRequestDuration(raw string) string {
	parsed, ok := dashboardParseRequestDuration(raw)
	if !ok {
		return strings.TrimSpace(raw)
	}
	return dashboardFormatDurationRounded(parsed)
}

func dashboardParseRequestDuration(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	// ParseDuration accepts "µs" but normalizing keeps this robust.
	raw = strings.ReplaceAll(raw, "μs", "us")
	raw = strings.ReplaceAll(raw, "µs", "us")
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, false
	}
	if parsed < 0 {
		parsed = 0
	}
	return parsed, true
}

// Match the single-tunnel dashboard rounding style.
func dashboardFormatDurationRounded(d time.Duration) string {
	return termui.FormatDurationRounded(d)
}

type upLatencyPercentilesValues struct {
	p50 string
	p90 string
	p95 string
	p99 string
}

func upLatencyPercentiles(samples []time.Duration) (upLatencyPercentilesValues, bool) {
	values, ok := termui.FormatLatencyPercentiles(samples, dashboardFormatDurationRounded)
	if !ok {
		return upLatencyPercentilesValues{}, false
	}
	return upLatencyPercentilesValues{
		p50: values.P50,
		p90: values.P90,
		p95: values.P95,
		p99: values.P99,
	}, true
}

func truncateRight(s string, n int) string {
	return termui.TruncateRight(s, n)
}

func shortenDashboardText(s string, max int) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	return truncateRight(s, max)
}
