package internal

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
)

// execOutputDrain bounds how long an exec command's status waits, once the
// command has exited, for the output still in its pipes to reach the guest.
// What keeps them open past that is a background child the command left
// behind, still holding its stdout: OpenSSH's sshd waits for it, but a guest
// here would be holding up the session's end, so the wait is bounded as a
// forced command's drain is.
const execOutputDrain = forceCommandDrainTimeout

// handleExec serves a guest's exec request with no pty -- `ssh <session>
// 'cmd'` -- under --allow-exec: the command runs through the host's $SHELL
// -c, as sshd runs one, as a process of its own that has nothing to do with
// the session's terminal. Its stdout and stderr are the guest's, its stdin is
// the guest's input until the guest sends EOF, and its exit status is the
// guest's, 128+N when it was killed by signal N, as a shell reports one.
//
// That is what a program driving a session needs -- an agent, a script --
// which can't drive a shared terminal: each command is a request and an
// answer, with nothing of the screen in between.
//
// The command is the guest's SSH session, so it is described as a forced
// command is (see startForceCommand). It is hung up when its guest leaves or
// the session ends, as a forced command is, and the session's end waits for
// that (see the execs tracker). An exec guest counts as a guest that joined:
// it claims the session, as a terminal or SFTP guest does, and that ends the
// join timeout.
func (h *sessionHandler) handleExec(sess gssh.Session) {
	if h.readonly {
		// The CLI refuses --allow-exec with --read-only; this is the door
		// keeping that promise whatever its caller did.
		_, _ = io.WriteString(sess.Stderr(), "upterm: this session is read-only; it doesn't run commands.\n")
		_ = sess.Exit(1)
		return
	}
	if h.ctx.Err() != nil {
		// Arrived as the session was ending: sent what any client arriving
		// then is (see exitLate), rather than a command started only to be
		// hung up.
		h.exitLate(sess)
		return
	}

	var auth *server.AuthRequest
	guest, isGuest := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest)
	if isGuest {
		auth = guest.auth
	}

	raw := sess.RawCommand()
	cmd := exec.Command(execShell(), "-c", raw)
	cmd.Env = append(withoutSSHSessionVars(os.Environ()), h.commandEnv...)
	cmd.Env = append(cmd.Env, guestConnectionEnv(auth, h.hideClientIP)...)
	setExecProcessGroup(cmd)
	cmd.Stdout = sess
	cmd.Stderr = sess.Stderr()
	cmd.WaitDelay = execOutputDrain
	// A pipe of its own rather than cmd.Stdin = sess: Wait waits for the
	// goroutine copying a non-file Stdin, and that goroutine reads until the
	// guest sends EOF, which `ssh <session> 'cmd'` typed at a terminal never
	// does. Every command would have waited out execOutputDrain after exiting.
	stdin, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		h.logger.Error("error starting guest exec command", "error", err)
		_, _ = io.WriteString(sess.Stderr(), "upterm: this session couldn't run your command; the host's log has why.\n")
		_ = sess.Exit(1)
		return
	}

	sessionID := sess.Context().SessionID()
	fingerprint := ""
	if isGuest {
		fingerprint = utils.FingerprintSHA256(guest.key)
		id := clientEventID(sessionID)
		emitClientJoinEvent(h.eventEmmiter, id, guest.auth, guest.key)
		defer emitClientLeftEvent(h.eventEmmiter, id)
	}
	h.logger.Info("guest exec command started", "command", raw, "pid", cmd.Process.Pid, "client", fingerprint)

	go func() {
		_, _ = io.Copy(stdin, sess)
		_ = stdin.Close()
	}()

	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()

	// The guest leaving is its connection going, or -- for a guest that
	// shares one connection between sessions, as ssh's ControlMaster does --
	// this session's channel being closed from its side. Nil for a session
	// the door did not build, a test's, which has only the connection.
	hungUp := false
	select {
	case <-exited:
	case <-h.ctx.Done():
		hungUp = true
	case <-sess.Context().Done():
		// The guest has gone: there is nobody to send a status to, and a
		// command left running would be nobody's.
		hungUp = true
	case <-channelClosed(sess):
		hungUp = true
	}
	if hungUp {
		terminateExec(cmd, exited, h.timing.hangup, h.timing.forceCommandStop, h.logger, raw)
	}

	select {
	case <-exited:
	default:
		// terminateExec gave up, and said so. There is no status to send.
		_ = sess.Exit(1)
		return
	}

	code := execExitCode(cmd, waitErr)
	h.logger.Info("guest exec command ended", "command", raw, "status", code, "hung_up", hungUp)
	if hungUp && h.ctx.Err() != nil {
		// Ended by the session's end, not on its own: what the command
		// returned while it was hung up is not its outcome, and a stop,
		// signal or cancellation is reported as every other client is told
		// it.
		if kind, sig, _, _ := h.endingCause(); kind.overrides() {
			h.exitWith(sess, kind.end(sig), 1)
			return
		}
	}
	_ = sess.Exit(code)
}

// execExitCode is the status a guest's exec command ended with, as a shell
// reports it: its exit code, or 128+N when signal N killed it.
func execExitCode(cmd *exec.Cmd, waitErr error) int {
	if _, n := signalOutcome(waitErr); n != nil {
		return 128 + *n
	}
	if code, ok := exitCode(waitErr); ok {
		return code
	}
	// ErrWaitDelay: the command exited, and execOutputDrain ran out on the
	// output a child of its was still holding. Its own status still stands.
	if errors.Is(waitErr, exec.ErrWaitDelay) && cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return 1
}

// execShell is the shell a guest's exec command runs through: the host's
// $SHELL, as sshd uses the user's, or /bin/sh.
func execShell() string {
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	return "/bin/sh"
}

// waitExited blocks for up to d, reporting whether exited closed within it.
func waitExited(exited <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-exited:
		return true
	case <-timer.C:
		return false
	}
}
