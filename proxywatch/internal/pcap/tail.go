package pcap

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// tailReader wraps an *os.File so Read blocks (with periodic polling)
// until either more data is available or ctx is cancelled. Pcapgo
// can't natively follow a growing file — io.ReadFull returns io.EOF
// permanently the moment the underlying reader runs out of bytes
// mid-record. We turn that into "wait for more bytes" by spinning a
// short poll loop until either new data shows up or the caller
// cancels via context, at which point we return io.EOF cleanly so
// pcapgo unwinds rather than seeing a custom error it doesn't know
// what to do with.
type tailReader struct {
	f             *os.File
	ctx           context.Context
	poll          time.Duration
	maxIdle       time.Duration // 0 = follow forever; nonzero stops after no growth
	lastIdleStart time.Time
}

// newTailReader opens path read-only and wraps it for tail-following.
// Returns the open *os.File so the caller can close it on shutdown.
// poll defaults to 100ms when zero.
//
// On Windows, the file is opened with explicit FILE_SHARE_READ |
// FILE_SHARE_WRITE | FILE_SHARE_DELETE flags via openSharedRead so
// WinDump (or any other writer) can keep appending packets while
// we tail-read. Plain os.Open on Windows uses FILE_SHARE_READ only,
// which silently blocks WinDump's writes — the operator sees a
// 24-byte (header-only) pcap that never grows. POSIX has no such
// constraint; openSharedRead is a no-op alias for os.Open there.
func newTailReader(ctx context.Context, path string, poll, maxIdle time.Duration) (*tailReader, *os.File, error) {
	f, err := openSharedRead(path)
	if err != nil {
		return nil, nil, err
	}
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	return &tailReader{
		f:       f,
		ctx:     ctx,
		poll:    poll,
		maxIdle: maxIdle,
	}, f, nil
}

// Read returns bytes from the underlying file. When the file's at
// EOF, Read sleeps `poll` and tries again, repeating until the file
// grows OR ctx is cancelled OR maxIdle elapses with no growth.
// Cancellation / idle-timeout returns io.EOF (not ctx.Err()) because
// pcapgo treats io.EOF as "clean stop" but turns other errors into
// noisy parse failures.
func (t *tailReader) Read(p []byte) (int, error) {
	for {
		if err := t.ctx.Err(); err != nil {
			return 0, io.EOF
		}
		n, err := t.f.Read(p)
		if n > 0 {
			t.lastIdleStart = time.Time{}
			return n, nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			// Real error (closed file, IO failure) — surface it.
			return 0, err
		}
		// EOF: file's caught up. Track when idle started so we can
		// optionally bail out after maxIdle of no growth.
		if t.lastIdleStart.IsZero() {
			t.lastIdleStart = time.Now()
		}
		if t.maxIdle > 0 && time.Since(t.lastIdleStart) >= t.maxIdle {
			return 0, io.EOF
		}
		// Sleep with cancellation. Using a timer instead of Sleep so
		// Esc / quit unwinds within `poll` worst-case.
		timer := time.NewTimer(t.poll)
		select {
		case <-t.ctx.Done():
			timer.Stop()
			return 0, io.EOF
		case <-timer.C:
		}
	}
}
