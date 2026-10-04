// Command netsim is a slow, lossy link in user space for the end-to-end
// test, where the kernel may lack netem. It takes packets from a TUN
// device and writes them back after a delay with jitter, dropping some at
// random; policy routing in the router sends the traffic of interest
// through the device, so every packet of it, acknowledgements included,
// gets the same treatment. Packets keep their order, as on a real link
// whose delay varies with queueing: jitter spreads them out but never
// reorders them (netem does reorder, which QUIC's loss detection counts
// as loss).
//
//	netsim -tun dly0 -params FILE
//
// The parameters file holds "delay=60ms", "jitter=5ms", "loss=10" (per
// mille) and optional "rate=4000000" (bits/second, aggregate) lines and is
// read again whenever it changes. Rate zero disables the bandwidth limit.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type params struct {
	delay, jitter time.Duration
	lossPerMille  int
	rate          int64
}

var current atomic.Pointer[params]

func (p *params) wait() time.Duration {
	d := p.delay
	if p.jitter > 0 {
		d += time.Duration(rand.Int64N(int64(2*p.jitter))) - p.jitter
	}
	return max(d, 0)
}

func readParams(path string) (*params, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p := &params{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		var err error
		switch k {
		case "delay":
			p.delay, err = time.ParseDuration(v)
		case "jitter":
			p.jitter, err = time.ParseDuration(v)
		case "loss":
			p.lossPerMille, err = strconv.Atoi(v)
		case "rate":
			p.rate, err = strconv.ParseInt(v, 10, 64)
		}
		if err != nil {
			return nil, err
		}
	}
	if p.rate < 0 || p.rate > 1_000_000_000_000 {
		return nil, fmt.Errorf("rate must be between 0 and 1000000000000 bits/second")
	}
	return p, sc.Err()
}

func watchParams(path string) {
	var last time.Time
	for {
		if st, err := os.Stat(path); err == nil && !st.ModTime().Equal(last) {
			if p, err := readParams(path); err == nil {
				current.Store(p)
				last = st.ModTime()
				log.Printf("delay %v jitter %v loss %d/1000 rate %dbit/s", p.delay, p.jitter, p.lossPerMille, p.rate)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func openTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func main() {
	tun := flag.String("tun", "dly0", "TUN device to create")
	paramsPath := flag.String("params", "", "file with delay=, jitter=, loss= and rate= lines")
	flag.Parse()
	current.Store(&params{})
	if *paramsPath != "" {
		go watchParams(*paramsPath)
	}
	dev, err := openTUN(*tun)
	if err != nil {
		log.Fatalf("creating %s: %v", *tun, err)
	}
	if out, err := exec.Command("ip", "link", "set", "dev", *tun, "up").CombinedOutput(); err != nil {
		log.Fatalf("bringing %s up: %v: %s", *tun, err, out)
	}
	log.Printf("%s up", *tun)
	// One writer sends the queued packets in order, each at its time; the
	// times never decrease, so the order is kept.
	queue := make(chan delayed, 1<<16)
	go func() {
		for d := range queue {
			time.Sleep(time.Until(d.due))
			_, _ = dev.Write(d.pkt)
		}
	}()
	buf := make([]byte, 65535)
	var lastDue time.Time
	for {
		n, err := dev.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		p := current.Load()
		if p.lossPerMille > 0 && rand.IntN(1000) < p.lossPerMille {
			continue
		}
		due := packetDue(time.Now(), lastDue, n, p)
		select {
		case queue <- delayed{due: due, pkt: append([]byte(nil), buf[:n]...)}:
			lastDue = due
		default: // the link's queue is full: dropped
		}
	}
}

type delayed struct {
	due time.Time
	pkt []byte
}

func packetDue(now, last time.Time, size int, p *params) time.Time {
	due := now.Add(p.wait())
	if p.rate > 0 {
		// Round up so even small packets consume bandwidth. A single queue
		// bounds the aggregate rate across both directions of the test link.
		bitsNS := int64(size) * 8 * int64(time.Second)
		if last.Before(now) {
			last = now
		}
		last = last.Add(time.Duration((bitsNS + p.rate - 1) / p.rate))
	}
	if last.After(due) {
		return last
	}
	return due
}
