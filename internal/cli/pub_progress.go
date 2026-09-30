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
	mu          sync.Mutex
	out         io.Writer
	interactive bool
	lastUpdate  time.Time
	active      bool
	notify      func(string)
}

func (p *pubProgress) start(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = true
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

func (r *pubUploadReader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	r.sent += int64(n)
	percent := float64(r.sent) / float64(r.total) * 100
	r.progress.update(fmt.Sprintf("Uploading: %s / %s (%.0f%%)", pubFormatBytes(float64(r.sent)), pubFormatBytes(float64(r.total)), percent))
	return n, err
}
