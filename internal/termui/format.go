package termui

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

func CapitalizeCSV(s string) string {
	parts := strings.Split(s, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			parts[i] = part
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, ", ")
}

func FormatDurationRounded(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dμs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func FormatDowntime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)
	seconds := int(d.Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%d %s", seconds, Pluralize(seconds, "second"))
	}
	minutes := seconds / 60
	if minutes < 60 {
		return fmt.Sprintf("%d %s", minutes, Pluralize(minutes, "minute"))
	}
	hours := minutes / 60
	minutes = minutes % 60
	if minutes == 0 {
		return fmt.Sprintf("%d %s", hours, Pluralize(hours, "hour"))
	}
	return fmt.Sprintf("%d %s, %d %s",
		hours, Pluralize(hours, "hour"),
		minutes, Pluralize(minutes, "minute"))
}

func Pluralize(n int, singular string) string {
	if n == 1 {
		return singular
	}
	return singular + "s"
}

type LatencyPercentiles struct {
	P50 string
	P90 string
	P95 string
	P99 string
}

func FormatLatencyPercentiles(samples []time.Duration, formatter func(time.Duration) string) (LatencyPercentiles, bool) {
	if len(samples) == 0 {
		return LatencyPercentiles{}, false
	}
	sorted := append([]time.Duration(nil), samples...)
	slices.Sort(sorted)
	return LatencyPercentiles{
		P50: formatter(DurationPercentile(sorted, 50)),
		P90: formatter(DurationPercentile(sorted, 90)),
		P95: formatter(DurationPercentile(sorted, 95)),
		P99: formatter(DurationPercentile(sorted, 99)),
	}, true
}

func DurationPercentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	n := len(sorted)
	idx := (p*n + 99) / 100
	if idx <= 0 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return sorted[idx-1]
}
