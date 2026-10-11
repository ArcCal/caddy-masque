package ipv6_test

import (
	"net"
	"testing"
)

func connector(t *testing.T, network, addr string, done chan<- bool) {
	t.Helper()
	defer func() { done <- true }()

	c, err := net.Dial(network, addr)
	if err != nil {
		t.Error(err)
		return
	}
	c.Close()
}

func acceptor(t *testing.T, ln net.Listener, done chan<- bool) {
	t.Helper()
	defer func() { done <- true }()

	c, err := ln.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	c.Close()
}
