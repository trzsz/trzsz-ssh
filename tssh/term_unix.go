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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/shlex"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var isRunningOnOldWindows atomic.Bool

type stdinState struct {
	fd    int
	state *term.State
}

func setupVirtualTerminal() error {
	return nil
}

func makeStdinRaw() (*stdinState, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("terminal make raw failed: %v", err)
	}
	return &stdinState{fd, state}, nil
}

func resetStdin(s *stdinState) {
	if s != nil && s.state != nil {
		_ = term.Restore(s.fd, s.state)
		s.state = nil
	}
}

func getTerminalSize() (int, int, error) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 0, 0, err
	}
	return width, height, nil
}

func onTerminalResize(setTerminalSize func(int, int)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if width, height, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				setTerminalSize(width, height)
			}
		}
	}()
	ch <- syscall.SIGWINCH
}

func getKeyboardInput() (*os.File, func(), error) {
	if isTerminal {
		return os.Stdin, func() {}, nil
	}

	file, err := os.Open("/dev/tty")
	if err != nil {
		return nil, nil, err
	}

	return file, func() { _ = file.Close() }, nil
}

func getStderrOutput() (*os.File, func(), error) {
	if isTerminal {
		return os.Stderr, func() {}, nil
	}

	file, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, err
	}

	return file, func() { _ = file.Close() }, nil
}

func isSshTmuxEnv() bool {
	if _, tmux := os.LookupEnv("TMUX"); !tmux {
		return false
	}

	cmd := exec.Command("tmux", "display-message", "-p", "#{client_pid}")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return false
	}

	return isRemoteSshEnv(pid)
}

func splitCommandLine(command string) ([]string, error) {
	return shlex.Split(command)
}

func suspendProcess() {
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGSTOP); err != nil {
		warning("suspend current process failed: %v", err)
		return
	}

	debug("current process is suspended")
}

type terminalController struct {
	fd  int
	raw bool

	mu sync.Mutex

	// state is the original terminal state to restore on exit.
	// It is kept across SIGCONT and foreground/background transitions.
	state *stdinState

	// rawActive indicates whether raw mode has been applied since the
	// last SIGCONT or confirmed transition to the background.
	rawActive    bool
	foreground   bool
	foregroundCh chan struct{}
	closed       bool

	// foregroundErr records a terminal foreground detection failure.
	foregroundErr error
	// fgCheckFails counts consecutive failed monitor checks.
	fgCheckFails int

	contCh    chan os.Signal
	wakeCh    chan struct{}
	doneCh    chan struct{}
	loopDone  chan struct{}
	closeOnce sync.Once

	onForeground    func()
	callbackPending bool

	// Optional hooks for tests.
	checkForeground func() (bool, error)
	makeRaw         func() (*stdinState, error)
	restore         func(*stdinState)

	interval time.Duration
	resetSig bool
}

func newTerminalController(raw bool) (*terminalController, error) {
	if !isTerminal {
		return nil, nil
	}

	// Ignore SIGTTIN so background terminal reads can return EIO.
	signal.Ignore(syscall.SIGTTIN)

	t := &terminalController{
		fd:           int(os.Stdin.Fd()),
		raw:          raw,
		foregroundCh: make(chan struct{}),
		contCh:       make(chan os.Signal, 1),
		wakeCh:       make(chan struct{}, 1),
		doneCh:       make(chan struct{}),
		loopDone:     make(chan struct{}),
		interval:     100 * time.Millisecond,
		resetSig:     true,
	}

	// Register before checking the initial foreground state.
	signal.Notify(t.contCh, syscall.SIGCONT)

	if err := t.start(); err != nil {
		signal.Stop(t.contCh)
		signal.Reset(syscall.SIGTTIN)
		return nil, err
	}

	return t, nil
}

func (t *terminalController) setOnForeground(fn func()) {
	t.mu.Lock()
	t.onForeground = fn
	t.mu.Unlock()
}

func (t *terminalController) start() error {
	t.mu.Lock()

	fg, err := t.isForegroundLocked()
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("get foreground process group failed: %v", err)
	}

	if fg {
		if err := t.enterRawLocked(); err != nil {
			t.mu.Unlock()
			return err
		}
	}

	t.setForegroundLocked(fg)
	t.mu.Unlock()

	go t.run()
	return nil
}

func (t *terminalController) isForegroundLocked() (bool, error) {
	if t.checkForeground != nil {
		fg, err := t.checkForeground()
		if err == nil {
			t.fgCheckFails = 0
		}
		return fg, err
	}

	for {
		pgid, err := unix.IoctlGetInt(t.fd, unix.TIOCGPGRP)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}

		t.fgCheckFails = 0

		return pgid == syscall.Getpgrp(), nil
	}
}

func (t *terminalController) setForegroundErrorLocked(err error) {
	if !t.closed && t.foregroundErr == nil {
		t.foregroundErr = err
		t.notifyWaitersLocked()
	}
}

// enterRawLocked applies raw mode if it is not currently active.
//
// The original state is saved only once. Subsequent calls to MakeRaw may
// return a snapshot of an already-raw terminal, which must not replace it.
func (t *terminalController) enterRawLocked() error {
	if !t.raw || t.rawActive {
		return nil
	}

	var (
		state *stdinState
		err   error
	)

	if t.makeRaw != nil {
		state, err = t.makeRaw()
	} else {
		state, err = makeStdinRaw()
	}

	if err != nil {
		return err
	}

	if state == nil {
		return errors.New("make stdin raw returned nil state")
	}

	if t.state == nil {
		t.state = state
	}

	t.rawActive = true
	return nil
}

func (t *terminalController) setForegroundLocked(fg bool) {
	if !fg {
		// The shell may have restored the terminal while we were in the
		// background. Raw mode must be applied again when we return.
		//
		// Do not clear t.state: it remains the original state to restore.
		t.rawActive = false
	}

	if t.foreground == fg {
		return
	}

	t.foreground = fg
	t.notifyWaitersLocked()

	if fg {
		t.requestForegroundCallbackLocked()
	}
}

func (t *terminalController) notifyWaitersLocked() {
	close(t.foregroundCh)
	t.foregroundCh = make(chan struct{})
}

// requestForegroundCallbackLocked schedules at most one callback at a time.
//
// The callback is asynchronous because RedrawScreen may take some time.
// Further requests while it is running are coalesced.
func (t *terminalController) requestForegroundCallbackLocked() {
	if t.closed || t.onForeground == nil || t.callbackPending {
		return
	}

	fn := t.onForeground
	t.callbackPending = true

	go func() {
		defer func() {
			t.mu.Lock()
			t.callbackPending = false
			t.mu.Unlock()
		}()

		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()

		if !closed {
			fn()
		}
	}()
}

func (t *terminalController) wake() {
	select {
	case <-t.doneCh:
		return
	default:
	}

	select {
	case t.wakeCh <- struct{}{}:
	default:
	}
}

// handleSIGCONT rechecks the actual foreground process group after SIGCONT.
//
// SIGCONT does not necessarily mean that the process has returned to the
// foreground. It may also be delivered to a process that was already running.
func (t *terminalController) handleSIGCONT() (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return false, nil
	}

	wasForeground := t.foreground

	// The shell may have restored the terminal while we were stopped.
	// Keep t.state because it contains the original state to restore.
	// Only mark raw mode inactive so it can be applied again.
	t.rawActive = false

	fg, err := t.isForegroundLocked()
	if err != nil {
		t.setForegroundLocked(false)
		return false, err
	}

	if !fg {
		t.setForegroundLocked(false)
		return false, nil
	}

	if err := t.enterRawLocked(); err != nil {
		t.setForegroundLocked(false)
		return false, err
	}

	t.setForegroundLocked(true)

	// If we were already marked as foreground, setForegroundLocked does not
	// trigger the callback. SIGCONT may nevertheless mean that the shell has
	// resumed the process and the screen needs to be redrawn.
	//
	// If another goroutine has already requested a redraw, the request is
	// coalesced by callbackPending.
	if wasForeground {
		t.requestForegroundCallbackLocked()
	}

	return true, nil
}

func (t *terminalController) run() {
	defer close(t.loopDone)

	interval := t.interval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	var (
		timer         *time.Timer
		timerC        <-chan time.Time
		fgWarned      bool
		rawModeWarned bool
		sigcontWarned bool
	)

	// The timer is owned exclusively by this goroutine.
	// A nil timerC disables the corresponding select case.
	//
	// Only one monitor timer is allowed at a time. Monitoring is active
	// while the controller is in the background state and stopped after
	// the foreground transition has been successfully completed.
	startMonitor := func() {
		if timer != nil {
			return
		}

		timer = time.NewTimer(interval)
		timerC = timer.C
	}

	stopMonitor := func() {
		if timer == nil {
			return
		}

		// Stop the timer and drain its channel if it has already fired.
		// This prevents a stale timer event from being processed later.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer = nil
		timerC = nil
	}

	// start() has already checked the initial foreground state.
	// Start polling only if the process initially started in the background.
	t.mu.Lock()
	if !t.closed && !t.foreground {
		startMonitor()
	}
	t.mu.Unlock()

	// Ensure the timer is stopped when the controller exits.
	defer stopMonitor()

	for {
		select {
		case <-t.doneCh:
			// Close() requested shutdown.
			return

		case <-t.contCh:
			// SIGCONT does not necessarily mean that the process has returned
			// to the foreground. Recheck the actual foreground process group
			// and reapply raw mode if necessary.
			fg, err := t.handleSIGCONT()
			if err != nil {
				// Avoid repeatedly logging the same consecutive error.
				if !sigcontWarned {
					warning("handle SIGCONT failed: %v", err)
					sigcontWarned = true
				}
			} else {
				sigcontWarned = false
			}

			if fg {
				// The process has returned to the foreground.
				// No background polling is needed.
				fgWarned = false
				rawModeWarned = false
				stopMonitor()
			} else {
				// The process is still in the background, or the foreground
				// check/raw mode restoration failed. Keep monitoring so the
				// process can recover when it actually returns to the foreground.
				startMonitor()
			}

		case <-t.wakeCh:
			// A waiter has requested that monitoring be updated, for example
			// [118;1:3uafter a background stdin read failed or a foreground check failed.
			// Read the current state under the mutex rather than relying on
			// the state that existed when the wake-up was sent.
			t.mu.Lock()
			fg := t.foreground
			closed := t.closed
			t.mu.Unlock()

			if closed || fg {
				stopMonitor()
			} else {
				startMonitor()
			}

		case <-timerC:
			// The timer has fired. Retire it before checking the state.
			// If monitoring must continue, start a new timer explicitly.
			timer = nil
			timerC = nil

			t.mu.Lock()

			// The process may have returned to the foreground, or the
			// controller may have been closed, since this timer was started.
			// In either case, this polling event is no longer needed.
			if t.closed || t.foreground {
				t.mu.Unlock()
				continue
			}

			fg, err := t.isForegroundLocked()
			if err != nil {
				// A failed check cannot confirm that the process is in the
				// foreground. Leave the foreground state unchanged and retry
				// after another polling interval.
				t.fgCheckFails++
				if t.fgCheckFails >= 100 {
					checkErr := fmt.Errorf("foreground monitor failed to query process group %d consecutive times: %v", t.fgCheckFails, err)
					t.setForegroundErrorLocked(checkErr)
					t.mu.Unlock()
					warning("terminal foreground monitoring stopped: %v", checkErr)
					return
				}

				t.mu.Unlock()

				if !fgWarned {
					warning("check foreground failed: %v", err)
					fgWarned = true
				}

				startMonitor()
				continue
			}

			fgWarned = false
			sigcontWarned = false

			if !fg {
				// The process is still in the background.
				// Keep raw mode inactive because the shell may have restored
				// the terminal attributes while this process was stopped.
				t.setForegroundLocked(false)
				t.mu.Unlock()

				// No raw mode restoration was needed, so allow a future
				// raw mode failure to be reported again.
				rawModeWarned = false
				startMonitor()
				continue
			}

			// The process has returned to the foreground. Reapply raw mode
			// before notifying waiters that input forwarding can resume.
			if err := t.enterRawLocked(); err != nil {
				// Do not report the process as foreground until raw mode
				// has been successfully applied.
				t.setForegroundLocked(false)
				t.mu.Unlock()

				if !rawModeWarned {
					warning("make stdin raw after returning to foreground failed: %v", err)
					rawModeWarned = true
				}

				// Keep polling so raw mode restoration can be retried.
				startMonitor()
				continue
			}
			rawModeWarned = false

			// This updates the foreground state, wakes waiters and requests
			// the foreground callback. The timer remains stopped.
			t.setForegroundLocked(true)
			t.mu.Unlock()
		}
	}
}

// waitUntilForeground waits until the process is in the foreground.
// It reports whether this call had to wait for foreground recovery.
func (t *terminalController) waitUntilForeground() (bool, error) {
	waited := false

	for {
		t.mu.Lock()

		if t.closed {
			t.mu.Unlock()
			return waited, errors.New("terminal controller closed")
		}

		if t.foregroundErr != nil {
			err := t.foregroundErr
			t.mu.Unlock()
			return waited, err
		}

		// Always check independently instead of trusting a notification.
		// A notification only indicates that the foreground state may have
		// changed; the actual process group must be checked again.
		fg, err := t.isForegroundLocked()
		if err != nil {
			// A failed check cannot confirm that we are in the foreground.
			// Treat the state as background so the monitor can retry.
			waited = true
			t.setForegroundLocked(false)

			// Capture the channel after updating the state. If the state
			// changed, setForegroundLocked may have closed the old channel.
			ch := t.foregroundCh
			t.mu.Unlock()

			// Let the monitor retry the foreground check.
			// This also ensures monitoring is active if a previous monitor
			// check failed and its timer is no longer running.
			t.wake()

			select {
			case <-t.doneCh:
				return waited, errors.New("terminal controller closed")
			case <-ch:
				// The monitor may have detected a state change.
				// Recheck the actual foreground process group.
				continue
			}
		}

		if fg {
			if err := t.enterRawLocked(); err != nil {
				// We cannot resume input forwarding until raw mode has been
				// successfully applied.
				waited = true
				t.setForegroundLocked(false)

				// Capture the channel after updating the foreground state.
				ch := t.foregroundCh
				t.mu.Unlock()

				// Let the monitor retry entering raw mode.
				t.wake()

				select {
				case <-t.doneCh:
					return waited, errors.New("terminal controller closed")
				case <-ch:
					// Wait for the monitor to successfully restore raw mode,
					// then recheck the actual foreground state.
					continue
				}
			}

			t.setForegroundLocked(true)
			t.mu.Unlock()

			// The monitor may still have a timer from the background state.
			// Wake it so it can stop monitoring promptly.
			t.wake()
			return waited, nil
		}

		// The process is confirmed to be in the background.
		// setForegroundLocked(false) also marks raw mode inactive because
		// the shell may restore terminal attributes while we are stopped.
		waited = true
		t.setForegroundLocked(false)

		// Capture the notification channel while holding the mutex to avoid
		// missing a foreground transition betwee[118;1:3un checking the state and
		// starting to wait.
		ch := t.foregroundCh

		t.mu.Unlock()

		// Ensure background polling is active, including after a previous
		// monitor check failed. If monitoring is already active, this is a
		// harmless wake-up.
		t.wake()

		select {
		case <-t.doneCh:
			return waited, errors.New("terminal controller closed")

		case <-ch:
			// Recheck the actual foreground process group instead of assuming
			// that the notification means we are now in the foreground.
		}
	}
}

func (t *terminalController) Close() {
	if t == nil {
		return
	}

	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.notifyWaitersLocked()
		t.mu.Unlock()

		if t.resetSig {
			signal.Stop(t.contCh)
		}

		close(t.doneCh)
		<-t.loopDone

		t.mu.Lock()

		if t.state != nil {
			// Do not restore terminal attributes while in the background.
			// The shell owns the terminal in that case, and tcsetattr may
			// generate SIGTTOU.
			fg, err := t.isForegroundLocked()
			if err == nil && fg {
				if t.restore != nil {
					t.restore(t.state)
				} else {
					resetStdin(t.state)
				}
			} else if err != nil {
				debug("skip terminal restore because foreground check failed: %v", err)
			}

			t.state = nil
		}

		t.rawActive = false
		t.mu.Unlock()

		if t.resetSig {
			signal.Reset(syscall.SIGTTIN)
		}
	})
}

func isBackgroundReadError(err error) bool {
	return errors.Is(err, syscall.EIO)
}

func injectConsoleSpace() error {
	return nil
}

func windowsDnsServers() []dnsServer {
	return nil
}
