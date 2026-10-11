package ipv6_test

import (
	"testing"

	"golang.org/x/net/ipv6"
)

func TestControlMessageParseWithFuzz(t *testing.T) {
	var cm ipv6.ControlMessage
	for _, fuzz := range []string{
		"\f\x00\x00\x00)\x00\x00\x00.\x00\x00\x00",
		"\f\x00\x00\x00)\x00\x00\x00,\x00\x00\x00",
	} {
		cm.Parse([]byte(fuzz))
	}
}
