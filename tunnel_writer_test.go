package masque

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

func capsuleTCPPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		client.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// Control and data senders share a writer in a live tunnel. Every capsule
// must remain whole across concurrent writes and per-capsule flushes.
func TestCapsuleWriterConcurrentTCP(t *testing.T) {
	client, server := capsuleTCPPair(t)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	buffered := bufio.NewWriterSize(client, 4096)
	w := capsuleWriter{w: buffered, flush: buffered.Flush}
	const workers, each = 8, 64
	done := make(chan error, 1)
	go func() {
		reader := newCapsuleReader(server)
		seen := make(map[uint64]bool)
		for range workers * each {
			c, err := reader.next()
			if err != nil {
				done <- err
				return
			}
			var id uint64
			switch c := c.(type) {
			case proto.Datagram:
				if len(c) < 8 {
					done <- fmt.Errorf("short datagram: %d", len(c))
					return
				}
				id = binary.BigEndian.Uint64(c[:8])
				if !bytes.Equal(c[8:], bytes.Repeat([]byte{byte(id)}, len(c)-8)) {
					done <- fmt.Errorf("payload changed: %d", id)
					return
				}
			case proto.AddressAssign:
				if len(c) != 1 || c[0].Prefix != netip.MustParsePrefix("192.0.2.1/32") {
					done <- fmt.Errorf("control capsule changed: %v", c)
					return
				}
				id = c[0].RequestID
			default:
				done <- fmt.Errorf("unexpected capsule %T", c)
				return
			}
			if seen[id] {
				done <- fmt.Errorf("duplicate capsule %d", id)
				return
			}
			seen[id] = true
		}
		done <- nil
	}()
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := range each {
				id := uint64(worker*each + n + 1)
				var c proto.Capsule
				if n%3 == 0 {
					c = proto.AddressAssign{{RequestID: id, Prefix: netip.MustParsePrefix("192.0.2.1/32")}}
				} else {
					data := bytes.Repeat([]byte{byte(id)}, 1280)
					binary.BigEndian.PutUint64(data, id)
					c = proto.Datagram(data)
				}
				if err := w.writeCapsule(c); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type capsuleFailWriter struct {
	bytes.Buffer
	err error
}

func (w *capsuleFailWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return w.Buffer.Write(p)
}

func TestCapsuleWriterErrors(t *testing.T) {
	want := errors.New("write failed")
	dst := &capsuleFailWriter{err: want}
	flushed := 0
	w := capsuleWriter{w: dst, flush: func() error { flushed++; return want }}
	c := proto.Datagram([]byte("owned bytes"))
	if err := w.writeCapsule(c); !errors.Is(err, want) || flushed != 0 {
		t.Fatalf("write error=%v flushes=%d", err, flushed)
	}
	dst.err = nil
	if err := w.writeCapsule(c); !errors.Is(err, want) || flushed != 1 {
		t.Fatalf("flush error=%v flushes=%d", err, flushed)
	}
	if !bytes.Equal(dst.Bytes(), proto.Append(nil, c)) {
		t.Fatal("wire bytes changed after failed write")
	}
	dst.Reset()
	w.flush = nil
	if err := w.writeCapsule(c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), proto.Append(nil, c)) {
		t.Fatal("wire bytes changed after failed flush")
	}
}

type capsuleWriteStarted struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (w *capsuleWriteStarted) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	return w.Conn.Write(p)
}

func TestCapsuleWriterDeadlineReleasesWaiters(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	notify := &capsuleWriteStarted{Conn: client, started: make(chan struct{})}
	w := capsuleWriter{w: notify}
	done := make(chan error, 2)
	go func() { done <- w.writeCapsule(proto.Datagram(make([]byte, 1280))) }()
	<-notify.started
	go func() { done <- w.writeCapsule(proto.AddressAssign{{Prefix: netip.MustParsePrefix("192.0.2.1/32")}}) }()
	if err := client.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("deadline error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("writer kept a canceled sender blocked")
		}
	}
}

func BenchmarkCapsuleWriterTCP(b *testing.B) {
	for _, size := range []int{64, 1280, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			client, server := capsuleTCPPair(b)
			finished := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, server); close(finished) }()
			buffered := bufio.NewWriterSize(client, 4096)
			w := capsuleWriter{w: buffered, flush: buffered.Flush}
			var c proto.Capsule = proto.Datagram(make([]byte, size))
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if err := w.writeCapsule(c); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			client.Close()
			<-finished
		})
	}
}

func TestCapsuleWriterBoundedRetention(t *testing.T) {
	w := capsuleWriter{w: io.Discard}
	for _, size := range []int{1280, 65535, 64, 1501, 65535, 1280} {
		if err := w.writeCapsule(proto.Datagram(bytes.Repeat([]byte{42}, size))); err != nil {
			t.Fatal(err)
		}
		if len(w.buf) != 0 || cap(w.buf) > maxRetainedCapsuleBuffer {
			t.Fatalf("after%d retained len%d cap%d", size, len(w.buf), cap(w.buf))
		}
	}
	// The small normal frame remains reusable after an exceptional large one.
	if cap(w.buf) < 1280 {
		t.Fatalf("normal buffer was discarded: cap%d", cap(w.buf))
	}
}
