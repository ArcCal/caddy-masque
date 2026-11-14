package qlog

import (
	"context"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// DefaultConnectionTracer retains the HTTP/3 tracer entry point used by Caddy.
// HTTP/3 registers its schema at package initialization; the QUIC tracer writes
// all registered schemas using the upstream QLOGDIR implementation.
// Deprecated: use qlog.DefaultConnectionTracer from the QUIC qlog package.
func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracer(ctx, isClient, connID)
}
