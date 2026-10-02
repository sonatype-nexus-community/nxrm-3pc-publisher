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

package settle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errNotReady = errors.New("not ready")

type errLog struct {
	mu   sync.Mutex
	errs []error
	keys []string
}

func (l *errLog) record(key string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	l.errs = append(l.errs, err)
}

func (l *errLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errs)
}

func newScheduler(t *testing.T, settle, maxWait time.Duration) (*Scheduler, *errLog) {
	t.Helper()
	l := &errLog{}
	s := New(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		Settle:    settle,
		MaxWait:   maxWait,
		Retryable: func(err error) bool { return errors.Is(err, errNotReady) },
		OnError:   l.record,
	})
	t.Cleanup(s.Stop)
	return s, l
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 2*time.Second, 5*time.Millisecond)
}

func TestScheduler(t *testing.T) {
	t.Run("a burst of events runs the work once", func(t *testing.T) {
		s, _ := newScheduler(t, 40*time.Millisecond, time.Second)
		var runs atomic.Int32
		for range 5 {
			s.Trigger("c", func(context.Context) error { runs.Add(1); return nil })
		}

		eventually(t, func() bool { return runs.Load() == 1 })
		time.Sleep(120 * time.Millisecond)
		assert.EqualValues(t, 1, runs.Load())
	})

	t.Run("each event restarts the settle timer", func(t *testing.T) {
		s, _ := newScheduler(t, 80*time.Millisecond, 2*time.Second)
		var ran atomic.Int64
		start := time.Now()
		fn := func(context.Context) error { ran.Store(time.Since(start).Milliseconds()); return nil }

		s.Trigger("c", fn)
		time.Sleep(50 * time.Millisecond)
		s.Trigger("c", fn)
		eventually(t, func() bool { return ran.Load() != 0 })

		assert.GreaterOrEqual(t, ran.Load(), int64(50+80-10), "work must wait a full settle after the last event")
	})

	t.Run("the latest run function wins", func(t *testing.T) {
		s, _ := newScheduler(t, 30*time.Millisecond, time.Second)
		var got atomic.Value
		s.Trigger("c", func(context.Context) error { got.Store("first"); return nil })
		s.Trigger("c", func(context.Context) error { got.Store("second"); return nil })

		eventually(t, func() bool { return got.Load() != nil })
		assert.Equal(t, "second", got.Load())
	})

	t.Run("incomplete work is retried until it succeeds", func(t *testing.T) {
		s, l := newScheduler(t, 20*time.Millisecond, 2*time.Second)
		var runs atomic.Int32
		s.Trigger("c", func(context.Context) error {
			if runs.Add(1) < 3 {
				return errNotReady
			}
			return nil
		})

		eventually(t, func() bool { return runs.Load() == 3 })
		time.Sleep(80 * time.Millisecond)
		assert.EqualValues(t, 3, runs.Load())
		assert.Zero(t, l.count(), "retries that end in success report nothing")
	})

	t.Run("work that never completes is reported once at MaxWait", func(t *testing.T) {
		s, l := newScheduler(t, 20*time.Millisecond, 150*time.Millisecond)
		var runs atomic.Int32
		s.Trigger("c", func(context.Context) error { runs.Add(1); return errNotReady })

		eventually(t, func() bool { return l.count() == 1 })
		settled := runs.Load()
		time.Sleep(100 * time.Millisecond)

		assert.Equal(t, settled, runs.Load(), "no further attempts after giving up")
		assert.Equal(t, 1, l.count())
		assert.Equal(t, "c", l.keys[0])
		assert.ErrorIs(t, l.errs[0], errNotReady)
	})

	t.Run("a permanent error is reported immediately and not retried", func(t *testing.T) {
		s, l := newScheduler(t, 20*time.Millisecond, 2*time.Second)
		permanent := errors.New("invalid SBOM")
		var runs atomic.Int32
		s.Trigger("c", func(context.Context) error { runs.Add(1); return permanent })

		eventually(t, func() bool { return l.count() == 1 })
		time.Sleep(100 * time.Millisecond)

		assert.EqualValues(t, 1, runs.Load())
		assert.ErrorIs(t, l.errs[0], permanent)
	})

	t.Run("trailing events after completion are ignored", func(t *testing.T) {
		s, _ := newScheduler(t, 20*time.Millisecond, time.Second)
		var runs atomic.Int32
		fn := func(context.Context) error { runs.Add(1); return nil }
		s.Trigger("c", fn)
		eventually(t, func() bool { return runs.Load() == 1 })

		s.Trigger("c", fn)
		s.Trigger("c", fn)
		time.Sleep(100 * time.Millisecond)

		assert.EqualValues(t, 1, runs.Load())
	})

	t.Run("trailing events after a permanent failure are ignored", func(t *testing.T) {
		s, l := newScheduler(t, 20*time.Millisecond, time.Second)
		var runs atomic.Int32
		fn := func(context.Context) error { runs.Add(1); return errors.New("bad") }
		s.Trigger("c", fn)
		eventually(t, func() bool { return l.count() == 1 })

		s.Trigger("c", fn)
		time.Sleep(100 * time.Millisecond)

		assert.EqualValues(t, 1, runs.Load())
		assert.Equal(t, 1, l.count(), "the failure must not be reported again")
	})

	t.Run("a handled key becomes eligible again after MaxWait", func(t *testing.T) {
		s, _ := newScheduler(t, 10*time.Millisecond, 80*time.Millisecond)
		var runs atomic.Int32
		fn := func(context.Context) error { runs.Add(1); return nil }
		s.Trigger("c", fn)
		eventually(t, func() bool { return runs.Load() == 1 })

		time.Sleep(120 * time.Millisecond)
		s.Trigger("c", fn)

		eventually(t, func() bool { return runs.Load() == 2 })
	})

	t.Run("different keys are independent", func(t *testing.T) {
		s, _ := newScheduler(t, 20*time.Millisecond, time.Second)
		var a, b atomic.Int32
		s.Trigger("a", func(context.Context) error { a.Add(1); return nil })
		s.Trigger("b", func(context.Context) error { b.Add(1); return nil })

		eventually(t, func() bool { return a.Load() == 1 && b.Load() == 1 })
	})

	t.Run("Stop cancels pending work", func(t *testing.T) {
		s, _ := newScheduler(t, 60*time.Millisecond, time.Second)
		var runs atomic.Int32
		s.Trigger("c", func(context.Context) error { runs.Add(1); return nil })

		s.Stop()
		time.Sleep(120 * time.Millisecond)

		assert.Zero(t, runs.Load())
		s.Trigger("c", func(context.Context) error { runs.Add(1); return nil })
		time.Sleep(100 * time.Millisecond)
		assert.Zero(t, runs.Load(), "a stopped scheduler accepts no events")
	})

	t.Run("Stop waits for running work and cancels its context", func(t *testing.T) {
		s, _ := newScheduler(t, 10*time.Millisecond, time.Second)
		started := make(chan struct{})
		var sawCancel atomic.Bool
		s.Trigger("c", func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			sawCancel.Store(true)
			return ctx.Err()
		})

		<-started
		s.Stop()

		assert.True(t, sawCancel.Load(), "Stop must not return before running work has finished")
	})

	t.Run("Touch extends a pending wait", func(t *testing.T) {
		s, _ := newScheduler(t, 80*time.Millisecond, 2*time.Second)
		var ran atomic.Int64
		start := time.Now()
		s.Trigger("c", func(context.Context) error { ran.Store(time.Since(start).Milliseconds()); return nil })

		time.Sleep(50 * time.Millisecond)
		s.Touch("c")
		eventually(t, func() bool { return ran.Load() != 0 })

		assert.GreaterOrEqual(t, ran.Load(), int64(50+80-10))
	})

	t.Run("Touch never starts work for an unknown key", func(t *testing.T) {
		s, l := newScheduler(t, 20*time.Millisecond, time.Second)
		s.Touch("never-triggered")
		time.Sleep(100 * time.Millisecond)

		assert.Zero(t, l.count())
	})

	t.Run("Touch does not restart a finished key", func(t *testing.T) {
		s, _ := newScheduler(t, 20*time.Millisecond, time.Second)
		var runs atomic.Int32
		s.Trigger("c", func(context.Context) error { runs.Add(1); return nil })
		eventually(t, func() bool { return runs.Load() == 1 })

		s.Touch("c")
		time.Sleep(100 * time.Millisecond)

		assert.EqualValues(t, 1, runs.Load())
	})
}
