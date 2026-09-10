//go:build !linux

package main

import (
	"errors"
	"sync"
	"time"
)

type atPort struct {
	fd      int
	mu      sync.Mutex
	buf     []byte
	stopped bool
	done    chan struct{}
}

func openPort(devPath string) (*atPort, error) {
	return nil, errors.New("raw rpm30 device transport is only supported on Linux modems")
}

func (p *atPort) close() {}

func (p *atPort) drain() {}

func (p *atPort) write(s string) {}

func (p *atPort) waitFor(tokens []string, wait time.Duration) string { return "" }

func (p *atPort) cmd(s string, wait time.Duration) string { return "" }

func sendPDU(devPath, pduHex string, tpduLen int, report bool) (bool, string) {
	return false, "raw rpm30 device transport is only supported on Linux modems"
}

func countDThreads() int {
	return 0
}
