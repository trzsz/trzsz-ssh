//go:build !windows

/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func newTestTerminalController(
	t *testing.T,
	raw bool,
	interval time.Duration,
	check func() (bool, error),
	makeRaw func() (*stdinState, error),
	restore func(*stdinState),
) *terminalController {
	t.Helper()

	c := &terminalController{
		raw:             raw,
		foregroundCh:    make(chan struct{}),
		contCh:          make(chan os.Signal, 1),
		wakeCh:          make(chan struct{}, 1),
		doneCh:          make(chan struct{}),
		loopDone:        make(chan struct{}),
		checkForeground: check,
		makeRaw:         makeRaw,
		restore:         restore,
		interval:        interval,
	}

	if err := c.start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(c.Close)
	return c
}

func waitForCondition(t *testing.T, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(time.Second)

	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}

	t.Fatal("condition was not satisfied")
}

func isControllerForeground(c *terminalController) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.foreground
}

func isControllerRawActive(c *terminalController) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rawActive
}

func controllerCallbackPending(c *terminalController) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callbackPending
}

func waitForCallback(t *testing.T, c *terminalController, calls chan struct{}) {
	t.Helper()

	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("foreground callback was not invoked")
	}

	waitForCondition(t, func() bool {
		return !controllerCallbackPending(c)
	})
}

func TestTerminalControllerInitialForeground(t *testing.T) {
	var (
		rawCount atomic.Int32
		state    = &stdinState{}
	)

	c := newTestTerminalController(
		t,
		true,
		10*time.Millisecond,
		func() (bool, error) {
			return true, nil
		},
		func() (*stdinState, error) {
			rawCount.Add(1)
			return state, nil
		},
		nil,
	)

	if !isControllerForeground(c) {
		t.Fatal("expected foreground")
	}

	if !isControllerRawActive(c) {
		t.Fatal("expected raw mode to be active")
	}

	if got := rawCount.Load(); got != 1 {
		t.Fatalf("make raw called %d times, want 1", got)
	}

	c.mu.Lock()
	gotState := c.state
	c.mu.Unlock()

	if gotState != state {
		t.Fatal("original terminal state was not saved")
	}

	waited, err := c.waitUntilForeground()
	if err != nil {
		t.Fatal(err)
	}
	if waited {
		t.Fatal("waitUntilForeground reported waiting while already in foreground")
	}

	if got := rawCount.Load(); got != 1 {
		t.Fatalf("make raw called %d times, want 1", got)
	}
}

func TestTerminalControllerBackgroundToForeground(t *testing.T) {
	var (
		foreground atomic.Bool
		rawCount   atomic.Int32
	)

	c := newTestTerminalController(
		t,
		true,
		5*time.Millisecond,
		func() (bool, error) {
			return foreground.Load(), nil
		},
		func() (*stdinState, error) {
			rawCount.Add(1)
			return &stdinState{}, nil
		},
		nil,
	)

	if isControllerForeground(c) {
		t.Fatal("expected background")
	}

	result := make(chan error, 1)

	go func() {
		_, err := c.waitUntilForeground()
		result <- err
	}()

	foreground.Store(true)

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground timed out")
	}

	if !isControllerForeground(c) {
		t.Fatal("expected foreground")
	}

	if !isControllerRawActive(c) {
		t.Fatal("expected raw mode to be active")
	}

	if got := rawCount.Load(); got != 1 {
		t.Fatalf("make raw called %d times, want 1", got)
	}
}

func TestTerminalControllerSIGCONTPreservesOriginalState(t *testing.T) {
	var (
		foreground    atomic.Bool
		rawCount      atomic.Int32
		restoreCount  atomic.Int32
		restoredState *stdinState
	)

	foreground.Store(true)

	originalState := &stdinState{fd: 10}

	c := newTestTerminalController(
		t,
		true,
		5*time.Millisecond,
		func() (bool, error) {
			return foreground.Load(), nil
		},
		func() (*stdinState, error) {
			n := rawCount.Add(1)
			if n == 1 {
				return originalState, nil
			}

			// Subsequent MakeRaw calls must not replace the original state.
			return &stdinState{fd: int(n)}, nil
		},
		func(state *stdinState) {
			restoredState = state
			restoreCount.Add(1)
		},
	)

	// Simulate returning to the background and receiving SIGCONT.
	foreground.Store(false)
	c.contCh <- syscall.SIGCONT

	waitForCondition(t, func() bool {
		return !isControllerForeground(c) && !isControllerRawActive(c)
	})

	c.mu.Lock()
	gotState := c.state
	c.mu.Unlock()

	if gotState != originalState {
		t.Fatal("original terminal state was discarded after SIGCONT")
	}

	// Return to the foreground.
	foreground.Store(true)

	if _, err := c.waitUntilForeground(); err != nil {
		t.Fatal(err)
	}

	if !isControllerForeground(c) || !isControllerRawActive(c) {
		t.Fatal("expected foreground with raw mode active")
	}

	if got := rawCount.Load(); got != 2 {
		t.Fatalf("make raw called %d times, want 2", got)
	}

	c.Close()

	if got := restoreCount.Load(); got != 1 {
		t.Fatalf("restore called %d times, want 1", got)
	}

	if restoredState != originalState {
		t.Fatal("Close did not restore the original terminal state")
	}
}

func TestTerminalControllerRepeatedSIGCONTInForeground(t *testing.T) {
	var (
		rawCount      atomic.Int32
		restoreCount  atomic.Int32
		restoredState *stdinState
	)

	originalState := &stdinState{fd: 20}

	c := newTestTerminalController(
		t,
		true,
		time.Hour,
		func() (bool, error) {
			return true, nil
		},
		func() (*stdinState, error) {
			n := rawCount.Add(1)
			if n == 1 {
				return originalState, nil
			}
			return &stdinState{fd: int(n)}, nil
		},
		func(state *stdinState) {
			restoredState = state
			restoreCount.Add(1)
		},
	)

	// Repeated SIGCONT while already in the foreground must not overwrite
	// the original terminal state.
	for i := 0; i < 3; i++ {
		ok, err := c.handleSIGCONT()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("handleSIGCONT returned false, want true")
		}
	}

	if got := rawCount.Load(); got != 4 {
		t.Fatalf("make raw called %d times, want 4", got)
	}

	c.mu.Lock()
	gotState := c.state
	c.mu.Unlock()

	if gotState != originalState {
		t.Fatal("repeated SIGCONT replaced the original terminal state")
	}

	if !isControllerRawActive(c) {
		t.Fatal("expected raw mode to be active")
	}

	c.Close()

	if got := restoreCount.Load(); got != 1 {
		t.Fatalf("restore called %d times, want 1", got)
	}

	if restoredState != originalState {
		t.Fatal("Close did not restore the original terminal state")
	}
}

func TestTerminalControllerWaitRetriesForegroundError(t *testing.T) {
	defer disableWarningForTest()()

	expectedErr := errors.New("foreground query failed")

	var calls atomic.Int32
	waitCheckFailed := make(chan struct{})

	c := newTestTerminalController(
		t,
		false,
		time.Hour,
		func() (bool, error) {
			switch calls.Add(1) {
			case 1:
				// Initial check.
				return false, nil
			case 2:
				// The waiter's foreground check fails.
				close(waitCheckFailed)
				return false, expectedErr
			default:
				return true, nil
			}
		},
		nil,
		nil,
	)
	defer c.Close()

	type waitResult struct {
		waited bool
		err    error
	}
	result := make(chan waitResult, 1)

	go func() {
		waited, err := c.waitUntilForeground()
		result <- waitResult{waited: waited, err: err}
	}()

	select {
	case <-waitCheckFailed:
	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not perform the expected check")
	}

	// Simulate returning to the foreground.
	c.contCh <- syscall.SIGCONT

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.waited {
			t.Fatal("expected waitUntilForeground to report waiting")
		}
	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not recover from foreground check error")
	}

	if got := calls.Load(); got < 4 {
		t.Fatalf("foreground checked %d times, want at least 4", got)
	}

	if !isControllerForeground(c) {
		t.Fatal("expected foreground")
	}
}

func TestTerminalControllerWaitRetriesAfterRawError(t *testing.T) {
	defer disableWarningForTest()()

	var (
		checkCalls atomic.Int32
		rawCalls   atomic.Int32
		rawFailed  = make(chan struct{})
	)

	c := newTestTerminalController(
		t,
		true,
		time.Hour,
		func() (bool, error) {
			// The initial check starts in the background.
			if checkCalls.Add(1) == 1 {
				return false, nil
			}

			return true, nil
		},
		func() (*stdinState, error) {
			if rawCalls.Add(1) == 1 {
				close(rawFailed)
				return nil, errors.New("make raw failed")
			}

			return &stdinState{}, nil
		},
		nil,
	)
	defer c.Close()

	type waitResult struct {
		waited bool
		err    error
	}
	result := make(chan waitResult, 1)

	go func() {
		waited, err := c.waitUntilForeground()
		result <- waitResult{waited: waited, err: err}
	}()

	select {
	case <-rawFailed:
	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not attempt to make stdin raw")
	}

	// Simulate returning to the foreground. The monitor retries raw mode
	// after receiving SIGCONT.
	c.contCh <- syscall.SIGCONT

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.waited {
			t.Fatal("expected waitUntilForeground to report waiting")
		}
	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not recover from make raw error")
	}

	if got := rawCalls.Load(); got != 2 {
		t.Fatalf("make raw called %d times, want 2", got)
	}

	if !isControllerForeground(c) {
		t.Fatal("expected foreground")
	}

	if !isControllerRawActive(c) {
		t.Fatal("expected raw mode to be active")
	}
}

func TestTerminalControllerCloseRestoresTerminal(t *testing.T) {
	var (
		rawCount     atomic.Int32
		restoreCount atomic.Int32
	)

	c := newTestTerminalController(
		t,
		true,
		10*time.Millisecond,
		func() (bool, error) {
			return true, nil
		},
		func() (*stdinState, error) {
			rawCount.Add(1)
			return &stdinState{}, nil
		},
		func(*stdinState) {
			restoreCount.Add(1)
		},
	)

	c.Close()
	c.Close()

	if got := rawCount.Load(); got != 1 {
		t.Fatalf("make raw called %d times, want 1", got)
	}

	if got := restoreCount.Load(); got != 1 {
		t.Fatalf("restore called %d times, want 1", got)
	}

	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	if state != nil {
		t.Fatal("terminal state was not cleared")
	}
}

func TestTerminalControllerCloseSkipsRestoreInBackground(t *testing.T) {
	var (
		foreground   atomic.Bool
		restoreCount atomic.Int32
	)

	foreground.Store(true)

	c := newTestTerminalController(
		t,
		true,
		time.Hour,
		func() (bool, error) {
			return foreground.Load(), nil
		},
		func() (*stdinState, error) {
			return &stdinState{}, nil
		},
		func(*stdinState) {
			restoreCount.Add(1)
		},
	)

	// Move to the background.
	foreground.Store(false)

	ok, err := c.handleSIGCONT()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("handleSIGCONT returned true, want false")
	}

	if isControllerRawActive(c) {
		t.Fatal("raw mode should be inactive in the background")
	}

	c.Close()

	if got := restoreCount.Load(); got != 0 {
		t.Fatalf("restore called %d times in the background, want 0", got)
	}
}

func TestTerminalControllerCloseWakesWaiter(t *testing.T) {
	var calls atomic.Int32

	c := newTestTerminalController(
		t,
		false,
		time.Hour,
		func() (bool, error) {
			calls.Add(1)
			return false, nil
		},
		nil,
		nil,
	)

	result := make(chan error, 1)

	go func() {
		_, err := c.waitUntilForeground()
		result <- err
	}()

	waitForCondition(t, func() bool {
		return calls.Load() >= 2
	})

	c.Close()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected controller closed error")
		}

	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not exit after Close")
	}
}

func TestTerminalControllerRawDisabled(t *testing.T) {
	var rawCount atomic.Int32

	c := newTestTerminalController(
		t,
		false,
		10*time.Millisecond,
		func() (bool, error) {
			return true, nil
		},
		func() (*stdinState, error) {
			rawCount.Add(1)
			return &stdinState{}, nil
		},
		nil,
	)

	waited, err := c.waitUntilForeground()
	if err != nil {
		t.Fatal(err)
	}
	if waited {
		t.Fatal("waitUntilForeground reported waiting while already in foreground")
	}

	if got := rawCount.Load(); got != 0 {
		t.Fatalf("make raw called %d times, want 0", got)
	}

	c.Close()
}

func TestTerminalControllerMonitorRetriesAfterForegroundError(t *testing.T) {
	defer disableWarningForTest()()

	expectedErr := errors.New("foreground query failed")

	var calls atomic.Int32

	c := newTestTerminalController(
		t,
		false,
		5*time.Millisecond,
		func() (bool, error) {
			switch calls.Add(1) {
			case 1:
				// Initial check.
				return false, nil
			case 2:
				// First monitor check fails.
				return false, expectedErr
			default:
				// The next monitor check succeeds.
				return true, nil
			}
		},
		nil,
		nil,
	)
	defer c.Close()

	waitForCondition(t, func() bool {
		return isControllerForeground(c)
	})

	if got := calls.Load(); got < 3 {
		t.Fatalf("foreground checked %d times, want at least 3", got)
	}
}

func TestTerminalControllerMonitorRetriesAfterRawError(t *testing.T) {
	defer disableWarningForTest()()

	expectedErr := errors.New("make raw failed")

	var (
		foreground atomic.Bool
		rawCalls   atomic.Int32
	)

	c := newTestTerminalController(
		t,
		true,
		5*time.Millisecond,
		func() (bool, error) {
			return foreground.Load(), nil
		},
		func() (*stdinState, error) {
			if rawCalls.Add(1) == 1 {
				return nil, expectedErr
			}
			return &stdinState{}, nil
		},
		nil,
	)
	defer c.Close()

	foreground.Store(true)

	waitForCondition(t, func() bool {
		return isControllerRawActive(c)
	})

	if got := rawCalls.Load(); got < 2 {
		t.Fatalf("make raw called %d times, want at least 2", got)
	}

	if !isControllerForeground(c) {
		t.Fatal("expected foreground")
	}
}

func TestTerminalControllerWaitFailsAfterRepeatedForegroundErrors(t *testing.T) {
	defer disableWarningForTest()()

	expectedErr := errors.New("foreground query failed")
	var calls atomic.Int32

	c := newTestTerminalController(
		t,
		false,
		2*time.Millisecond,
		func() (bool, error) {
			if calls.Add(1) == 1 {
				// Initial state is background.
				return false, nil
			}
			return false, expectedErr
		},
		nil,
		nil,
	)
	defer c.Close()

	result := make(chan error, 1)

	go func() {
		_, err := c.waitUntilForeground()
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected foreground check error")
		}
	case <-time.After(time.Second):
		t.Fatal("waitUntilForeground did not return after repeated foreground check failures")
	}
}

func TestTerminalControllerOnForeground(t *testing.T) {
	calls := make(chan struct{}, 4)

	c := &terminalController{
		foregroundCh: make(chan struct{}),
		onForeground: func() {
			calls <- struct{}{}
		},
	}

	setForeground := func(fg bool) {
		c.mu.Lock()
		c.setForegroundLocked(fg)
		c.mu.Unlock()
	}

	setForeground(true)
	waitForCallback(t, c, calls)

	// Already foreground: do not invoke again.
	setForeground(true)

	// Foreground -> background.
	setForeground(false)

	// Background -> foreground.
	setForeground(true)
	waitForCallback(t, c, calls)

	// No additional callback should be pending.
	select {
	case <-calls:
		t.Fatal("unexpected extra foreground callback")
	default:
	}
}

func TestTerminalControllerOnForegroundAfterSIGCONT(t *testing.T) {
	calls := make(chan struct{}, 4)

	var foreground atomic.Bool
	foreground.Store(true)

	c := &terminalController{
		foreground:   true,
		foregroundCh: make(chan struct{}),
		checkForeground: func() (bool, error) {
			return foreground.Load(), nil
		},
		onForeground: func() {
			calls <- struct{}{}
		},
	}

	// SIGCONT while already in the foreground should request a redraw.
	ok, err := c.handleSIGCONT()
	if err != nil {
		t.Fatalf("handleSIGCONT failed: %v", err)
	}
	if !ok {
		t.Fatal("handleSIGCONT returned false, want true")
	}

	waitForCallback(t, c, calls)

	// SIGCONT while still in the background should not request a redraw.
	foreground.Store(false)

	ok, err = c.handleSIGCONT()
	if err != nil {
		t.Fatalf("handleSIGCONT failed: %v", err)
	}
	if ok {
		t.Fatal("handleSIGCONT returned true, want false")
	}

	select {
	case <-calls:
		t.Fatal("foreground callback invoked while still in background")
	default:
	}

	// Returning to the foreground should request a redraw.
	foreground.Store(true)

	c.mu.Lock()
	c.setForegroundLocked(true)
	c.mu.Unlock()

	waitForCallback(t, c, calls)

	// Repeated foreground checks must not trigger another callback.
	c.mu.Lock()
	c.setForegroundLocked(true)
	c.mu.Unlock()

	select {
	case <-calls:
		t.Fatal("foreground callback invoked more than once")
	default:
	}
}

type forwardInputStep struct {
	data []byte
	err  error
}

type forwardInputTestReader struct {
	steps []forwardInputStep
	calls int
}

func (r *forwardInputTestReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > len(r.steps) {
		return 0, io.EOF
	}

	step := r.steps[r.calls-1]
	return copy(p, step.data), step.err
}

type forwardInputTestWriter struct {
	bytes.Buffer
}

func (*forwardInputTestWriter) Close() error {
	return nil
}

func TestForwardInputResumesAfterBackgroundEIO(t *testing.T) {
	var foreground atomic.Bool

	terminal := &terminalController{
		foregroundCh: make(chan struct{}),
		wakeCh:       make(chan struct{}, 1),
		doneCh:       make(chan struct{}),
		checkForeground: func() (bool, error) {
			return foreground.Load(), nil
		},
	}

	// Simulate the monitor detecting the foreground transition.
	monitorDone := make(chan struct{})

	go func() {
		defer close(monitorDone)

		<-terminal.wakeCh

		foreground.Store(true)

		terminal.mu.Lock()
		terminal.setForegroundLocked(true)
		terminal.mu.Unlock()
	}()

	reader := &forwardInputTestReader{
		steps: []forwardInputStep{
			{err: syscall.EIO},
			{data: []byte("input")},
		},
	}
	writer := &forwardInputTestWriter{}

	conn := &sshConnection{
		param:    &sshParam{args: &sshArgs{}},
		terminal: terminal,
	}

	forwardInput(reader, writer, false, 0, 0, conn)

	select {
	case <-monitorDone:
	case <-time.After(time.Second):
		t.Fatal("foreground monitor did not exit")
	}

	if got := writer.String(); got != "input" {
		t.Fatalf("forwarded input = %q, want %q", got, "input")
	}

	if reader.calls != 3 {
		t.Fatalf("reader called %d times, want 3", reader.calls)
	}
}

func TestForwardInputStopsAfterRepeatedForegroundEIO(t *testing.T) {
	defer disableWarningForTest()()

	terminal := &terminalController{
		foreground:   true,
		foregroundCh: make(chan struct{}),
		wakeCh:       make(chan struct{}, 1),
		doneCh:       make(chan struct{}),
		checkForeground: func() (bool, error) {
			return true, nil
		},
	}

	reader := &forwardInputTestReader{
		steps: []forwardInputStep{
			{err: syscall.EIO},
			{err: syscall.EIO},
		},
	}
	writer := &forwardInputTestWriter{}

	conn := &sshConnection{
		param:    &sshParam{args: &sshArgs{}},
		terminal: terminal,
	}

	forwardInput(reader, writer, false, 0, 0, conn)

	if reader.calls != 2 {
		t.Fatalf("reader called %d times, want 2", reader.calls)
	}
}

func TestForwardInputResetsForegroundEIOAfterSuccessfulRead(t *testing.T) {
	defer disableWarningForTest()()

	terminal := &terminalController{
		foreground:   true,
		foregroundCh: make(chan struct{}),
		wakeCh:       make(chan struct{}, 1),
		doneCh:       make(chan struct{}),
		checkForeground: func() (bool, error) {
			return true, nil
		},
	}

	reader := &forwardInputTestReader{
		steps: []forwardInputStep{
			{err: syscall.EIO},
			{data: []byte("a")},
			{err: syscall.EIO},
			{data: []byte("b")},
		},
	}
	writer := &forwardInputTestWriter{}

	conn := &sshConnection{
		param:    &sshParam{args: &sshArgs{}},
		terminal: terminal,
	}

	forwardInput(reader, writer, false, 0, 0, conn)

	if got := writer.String(); got != "ab" {
		t.Fatalf("forwarded input = %q, want %q", got, "ab")
	}

	if reader.calls != 5 {
		t.Fatalf("reader called %d times, want 5", reader.calls)
	}
}
