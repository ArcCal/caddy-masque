package http2

import "time"

const (
	InitialHeaderTableSize = initialHeaderTableSize
	InitialWindowSize      = initialWindowSize
)

type (
	ServerConn = serverConn
)

func SummarizeFrame(f Frame) string {
	return summarizeFrame(f)
}

const GoAwayTimeout = 25 * time.Millisecond
