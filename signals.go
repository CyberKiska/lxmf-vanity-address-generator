package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

type signalPhase struct {
	name string
	ack  chan struct{}
}
type signalOwner struct {
	phases   chan signalPhase
	recovery chan os.Signal
	stop     chan struct{}
	done     chan struct{}
}

// Only this goroutine consumes OS notifications. Phase transitions discard
// earlier queued signals so search/save interrupts cannot confirm recovery loss.
func newSignalOwner(input <-chan os.Signal, cancel context.CancelFunc) *signalOwner {
	owner := &signalOwner{phases: make(chan signalPhase), recovery: make(chan os.Signal, 16), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(owner.done)
		phase := "search"
		for {
			select {
			case <-owner.stop:
				return
			case req := <-owner.phases:
				for {
					select {
					case <-input:
					default:
						goto drained
					}
				}
			drained:
				phase = req.name
				for {
					select {
					case <-owner.recovery:
					default:
						goto emptied
					}
				}
			emptied:
				close(req.ack)
			case sig := <-input:
				if phase == "search" {
					cancel()
				}
				if phase == "recovery" && sig == os.Interrupt {
					select {
					case owner.recovery <- sig:
					default:
					}
				}
			}
		}
	}()
	return owner
}
func (o *signalOwner) phase(name string) {
	ack := make(chan struct{})
	o.phases <- signalPhase{name, ack}
	<-ack
}
func (o *signalOwner) close() { close(o.stop); <-o.done }
func processSignals() (chan os.Signal, func()) {
	signals := make(chan os.Signal, 16)
	signal.Ignore(syscall.SIGPIPE)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return signals, func() { signal.Stop(signals) }
}
