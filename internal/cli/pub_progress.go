package cli

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// pubProgress keeps terminal updates on one line and logs only stage boundaries
// when output is redirected. Finish also suppresses late HTTP transport reads.
// Progress output is best-effort and must not interrupt an upload.
type pubProgress struct {
	mu            sync.Mutex
	out           io.Writer
	interactive   bool
	lastUpdate    time.Time
	active        bool
	notify        func(string)
	notifyUpload  func(int)
	uploadPercent int
}

func (p *pubProgress) start(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = true
	p.uploadPercent = -1
	p.lastUpdate = time.Now()
	if p.notify != nil {
		p.notify(text)
	}
	if p.interactive {
		_, _ = fmt.Fprintf(p.out, "\r\x1b[2K%s", text)
	} else {
		_, _ = fmt.Fprintln(p.out, text)
	}
}

func (p *pubProgress) update(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || !p.interactive || time.Since(p.lastUpdate) < 100*time.Millisecond {
		return
	}
	_, _ = fmt.Fprintf(p.out, "\r\x1b[2K%s", text)
	p.lastUpdate = time.Now()
	if p.notify != nil {
		p.notify(text)
	}
}

func (p *pubProgress) finish(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.interactive && p.active {
		_, _ = fmt.Fprint(p.out, "\r\x1b[2K")
	}
	p.active = false
	_, _ = fmt.Fprintln(p.out, text)
	if p.notify != nil {
		p.notify(text)
	}
}

func (p *pubProgress) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active && p.interactive {
		_, _ = fmt.Fprintln(p.out)
	}
	p.active = false
}

type pubUploadReader struct {
	r           io.Reader
	progress    *pubProgress
	total, sent int64
}

func (p *pubProgress) upload(sent, total int64) {
	if total <= 0 {
		return
	}
	percent := min(100, max(0, int(float64(sent)*100/float64(total))))
	p.mu.Lock()
	if p.active && p.notifyUpload != nil && percent != p.uploadPercent {
		p.uploadPercent = percent
		p.notifyUpload(percent)
	}
	p.mu.Unlock()
	p.update(fmt.Sprintf("Uploading: %s / %s (%d%%)", pubFormatBytes(float64(sent)), pubFormatBytes(float64(total)), percent))
}

func (r *pubUploadReader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	r.sent += int64(n)
	if n > 0 {
		r.progress.upload(r.sent, r.total)
	}
	return n, err
}
