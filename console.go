package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// One goroutine owns stderr. Status messages never hold up saving a winner.
// Closing cannot cancel an arbitrary Writer; a blocked writer may outlive run.
type console struct {
	messages chan string
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
}

func newConsole(writer io.Writer) *console {
	c := &console{messages: make(chan string, 16), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for message := range c.messages {
			_, _ = io.WriteString(writer, message)
		}
	}()
	return c
}
func (c *console) status(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.messages <- message:
	default:
	}
}
func (c *console) close(timeout time.Duration) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if !c.closed {
		c.closed = true
		close(c.messages)
	}
	c.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
	}
}
