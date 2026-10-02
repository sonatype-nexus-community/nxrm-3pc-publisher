/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package settle coalesces bursts of events for the same key into a single
// unit of work that runs once the burst has gone quiet. `serve` uses it
// because NXRM sends many webhook events for one component while its files
// are still arriving, and publishing has to wait until the component is
// complete.
package settle

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/logging"
)

// Options configures a Scheduler.
type Options struct {
	// Settle is how long a key must see no new events before its work runs,
	// and also the pause between retries of incomplete work.
	Settle time.Duration
	// MaxWait bounds how long a key may stay pending from its first event.
	// Once exceeded, incomplete work is reported through OnError and dropped.
	MaxWait time.Duration
	// Retryable reports whether a work error means "not ready yet, try
	// again" (true) or a permanent failure (false).
	Retryable func(error) bool
	// OnError receives permanent failures and timeouts. It is the single
	// place a failure is reported, so it is where the caller should log it.
	OnError func(key string, err error)
}

// Scheduler runs one function per key after that key's events settle.
type Scheduler struct {
	opts   Options
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	stopped bool
	pending map[string]*entry
	// finished remembers keys that already ran to a conclusion (published, or
	// failed permanently) so the trailing events from the same burst don't
	// start the work again. Entries expire after MaxWait.
	finished map[string]time.Time
	wg       sync.WaitGroup
}

type entry struct {
	first   time.Time
	timer   *time.Timer
	running bool
	run     func(ctx context.Context) error
}

// New returns a Scheduler whose work is cancelled when ctx is, or when Stop
// is called. logger must not be nil.
func New(ctx context.Context, logger *slog.Logger, opts Options) *Scheduler {
	ctx, cancel := context.WithCancel(ctx)
	return &Scheduler{
		opts:     opts,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		pending:  make(map[string]*entry),
		finished: make(map[string]time.Time),
	}
}

// Trigger records an event for key. The latest run function supplied for a
// key is the one used, so it may close over the most recent event's data.
// Events for a key that is currently running, or that finished within
// MaxWait, are dropped.
func (s *Scheduler) Trigger(key string, run func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	now := time.Now()
	s.expireFinished(now)

	if _, done := s.finished[key]; done {
		s.logger.Log(s.ctx, logging.LevelTrace, "ignoring event: key already handled", "key", key)
		return
	}

	e, ok := s.pending[key]
	if !ok {
		e = &entry{first: now}
		s.pending[key] = e
	}
	e.run = run
	if e.running {
		s.logger.Log(s.ctx, logging.LevelTrace, "event arrived while work is running", "key", key)
		return
	}
	s.arm(key, e, now)
}

// Touch records an event for key only if work for it is already pending and
// not running, restarting its settle timer. An event for an unknown key is
// ignored, so a signal that merely indicates activity (such as an NXRM
// component UPDATED) can extend a wait in progress without ever starting one.
func (s *Scheduler) Touch(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	if e, ok := s.pending[key]; ok && !e.running {
		s.arm(key, e, time.Now())
	}
}

// Stop cancels pending work, stops accepting events, and waits for work that
// is already running to return.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	s.stopped = true
	for _, e := range s.pending {
		if e.timer != nil {
			e.timer.Stop()
		}
	}
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// arm (re)starts the key's settle timer. The delay never pushes the run past
// the key's MaxWait deadline. Callers must hold s.mu.
func (s *Scheduler) arm(key string, e *entry, now time.Time) {
	if e.timer != nil {
		e.timer.Stop()
	}
	delay := s.opts.Settle
	if remaining := e.first.Add(s.opts.MaxWait).Sub(now); remaining < delay {
		delay = max(remaining, 0)
	}
	e.timer = time.AfterFunc(delay, func() { s.fire(key) })
}

func (s *Scheduler) fire(key string) {
	s.mu.Lock()
	e, ok := s.pending[key]
	if !ok || s.stopped {
		s.mu.Unlock()
		return
	}
	e.running = true
	run := e.run
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	err := run(s.ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	e.running = false
	now := time.Now()

	switch {
	case err == nil:
		delete(s.pending, key)
		s.finished[key] = now
	case s.ctx.Err() != nil:
		delete(s.pending, key)
	case s.opts.Retryable(err) && now.Sub(e.first) < s.opts.MaxWait:
		s.logger.Info("component not complete yet, will check again", "key", key, "reason", err.Error(), "retryIn", s.opts.Settle)
		s.arm(key, e, now)
	default:
		delete(s.pending, key)
		s.finished[key] = now
		s.opts.OnError(key, err)
	}
}

// expireFinished drops finished entries older than MaxWait. Callers must
// hold s.mu.
func (s *Scheduler) expireFinished(now time.Time) {
	for k, t := range s.finished {
		if now.Sub(t) > s.opts.MaxWait {
			delete(s.finished, k)
		}
	}
}
