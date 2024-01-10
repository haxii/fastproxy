package server

import (
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/log/v2"

	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Server a simple connection server
type Server struct {
	// Concurrency server concurrency
	Concurrency int
	// OnConcurrencyLimitExceeded called when the concurrency
	// limit exceeds, before the conn is force closed
	OnConcurrencyLimitExceeded func(net.Conn)

	// Listener server's listener
	Listener net.Listener
	// connections handler
	ConnHandler ConnHandler

	// ServiceName, server's service name, used for logging
	ServiceName string

	// active connections
	activeConn map[net.Conn]struct{}
	mu         sync.Mutex
}

// DefaultConcurrency is the maximum number of concurrent connections
const DefaultConcurrency = 256 * 1024

// ListenAndServe serves incoming connections from the given listener.
//
// Serve blocks until the given listener returns permanent error.
func (s *Server) ListenAndServe() error {
	if s.Listener == nil {
		return errors.New("No net.listener provided")
	}
	if s.ConnHandler == nil {
		return errors.New("No connection handler provided")
	}

	if s.Concurrency <= 0 {
		s.Concurrency = DefaultConcurrency
	}
	if len(s.ServiceName) == 0 {
		s.ServiceName = "fastproxy.server"
	}

	var lastOverflowErrorTime time.Time
	var lastPerIPErrorTime time.Time
	var c net.Conn
	var err error

	wp := &WorkerPool{
		WorkerFunc:      s.ConnHandler,
		Tracker:         s.trackConn,
		MaxWorkersCount: s.Concurrency,
	}
	wp.Start()

	for {
		if c, err = s.acceptConn(s.Listener, &lastPerIPErrorTime); err != nil {
			wp.Stop()
			if err == io.EOF {
				return nil
			}
			return err
		}
		if !wp.Serve(c) {
			if s.OnConcurrencyLimitExceeded != nil {
				s.OnConcurrencyLimitExceeded(c)
			}
			c.Close()
			if time.Since(lastOverflowErrorTime) > time.Minute {
				log.Errorf(errors.New("concurrency exceeded"), "The incoming connection cannot be served, "+
					"because %d concurrent connections are served. Try increasing server's concurrency",
					s.Concurrency)
				lastOverflowErrorTime = servertime.CoarseTimeNow()
			}
			time.Sleep(100 * time.Millisecond)
		}
		c = nil
	}
}

func (s *Server) acceptConn(ln net.Listener, lastPerIPErrorTime *time.Time) (net.Conn, error) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if c != nil {
				panic("BUG: net.Listener returned non-nil conn and non-nil error")
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Errorf(netErr, "temporary error when accepting new connections")
				time.Sleep(time.Second)
				continue
			}
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Errorf(err, "permanent error when accepting new connections")
				return nil, err
			}
			return nil, io.EOF
		}
		if c == nil {
			panic("BUG: net.Listener returned (nil, nil)")
		}
		return c, nil
	}
}

// Close close the server and close all the active connections
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Listener.Close()
	for c := range s.activeConn {
		c.Close()
		delete(s.activeConn, c)
	}
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConn == nil {
		s.activeConn = make(map[net.Conn]struct{})
	}
	if add {
		s.activeConn[c] = struct{}{}
	} else {
		delete(s.activeConn, c)
	}
}
