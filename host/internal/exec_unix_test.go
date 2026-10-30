//go:build !windows

package internal

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// execGuest runs cmd as a guest's exec request with no pty, returning what it
// wrote to stdout and stderr and what Wait said.
func execGuest(t *testing.T, client *ssh.Client, cmd string) (string, string, error) {
	t.Helper()
	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	err = sess.Run(cmd)
	return stdout.String(), stderr.String(), err
}

// A guest's command runs through a shell, as sshd runs one: a pipeline, a
// redirect and an exit status all mean what they mean at a prompt, and stdout
// and stderr arrive apart.
func TestExecRunsTheGuestsCommandThroughAShell(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})

	stdout, stderr, err := execGuest(t, h.guestClient(t), `printf 'one\ntwo\n' | tr a-z A-Z; echo oops >&2; exit 3`)
	requireExitStatus(t, err, 3)
	require.Equal(t, "ONE\nTWO\n", stdout)
	require.Equal(t, "oops\n", stderr)
}

// The guest's input is the command's, up to the guest's EOF.
func TestExecPassesTheGuestsInput(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})

	sess, err := h.guestClient(t).NewSession()
	require.NoError(t, err)
	sess.Stdin = strings.NewReader("from the guest\n")
	out, err := sess.Output("cat")
	require.NoError(t, err)
	require.Equal(t, "from the guest\n", string(out))
}

// `ssh SESSION 'cmd'` typed at a terminal never sends EOF on its own, and the
// command's status mustn't wait for one: a command that ignores its input is
// done when it exits, not execOutputDrain later.
func TestExecDoesNotWaitForAGuestThatNeverSendsEOF(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})

	sess, err := h.guestClient(t).NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()
	var stdout bytes.Buffer
	sess.Stdout = &stdout

	start := time.Now()
	require.NoError(t, sess.Run("echo hi"))
	require.Equal(t, "hi\n", stdout.String())
	require.Less(t, time.Since(start), execOutputDrain, "the status waited on the guest's input")
}

// A command killed by a signal reports 128+N, as a shell does, rather than
// the -1 exec gives, which would reach the guest as 4294967295.
func TestExecReportsASignalAs128PlusItsNumber(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})

	_, _, err := execGuest(t, h.guestClient(t), "kill -TERM $$")
	requireExitStatus(t, err, 128+int(syscall.SIGTERM))
}

// Without --allow-exec, a guest that asks for a command and no terminal is
// refused, as it always was.
func TestExecIsRefusedWithoutAllowExec(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 0)})

	stdout, _, err := execGuest(t, h.guestClient(t), "touch should-not-exist")
	requireExitStatus(t, err, 1)
	require.Contains(t, stdout, "this session needs a terminal")
}

// The CLI refuses --allow-exec with --read-only; the door refuses the command
// too, whatever its caller did.
func TestExecIsRefusedInAReadOnlySession(t *testing.T) {
	dir := t.TempDir()
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true, ReadOnly: true})

	marker := filepath.Join(dir, "ran")
	_, stderr, err := execGuest(t, h.guestClient(t), "touch "+marker)
	requireExitStatus(t, err, 1)
	require.Equal(t, "upterm: this session is read-only; it doesn't run commands.\n", stderr)
	require.NoFileExists(t, marker)
}

// An exec guest is a guest that joined: the session is told, as it is of a
// terminal or SFTP guest, and that is what ends the join timeout.
func TestExecGuestIsAJoinedGuest(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})
	joined := h.srv.EventEmitter.On(upterm.EventClientJoined)
	defer h.srv.EventEmitter.Off(upterm.EventClientJoined, joined)

	go func() { _, _, _ = execGuest(t, h.guestClient(t), "true") }()
	select {
	case evt := <-joined:
		client, ok := evt.Args[0].(*api.Client)
		require.True(t, ok)
		require.Equal(t, api.Client_GUEST, client.Kind)
	case <-time.After(harnessTimeout):
		t.Fatal("no guest joined")
	}
}

// requireGone waits for pid to be gone, failing the test if it outlives d.
func requireGone(t *testing.T, pid int, d time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) == syscall.ESRCH
	}, d, 20*time.Millisecond, "process %d is still running", pid)
}

// readPid waits for the command to have written its child's pid to path.
func readPid(t *testing.T, path string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.HasSuffix(b, []byte("\n")) {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, harnessTimeout, 20*time.Millisecond)
	return pid
}

// A guest that leaves takes its command with it, and everything the command
// started: a command left running would be nobody's.
func TestExecGuestLeavingHangsUpItsCommandsGroup(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})
	pidFile := filepath.Join(t.TempDir(), "pid")

	client := h.guestClient(t)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("sleep 60 & echo $! > "+pidFile+"; wait"))
	child := readPid(t, pidFile)

	require.NoError(t, client.Close())
	requireGone(t, child, harnessTimeout)
}

// A guest that closes its session's channel while keeping the connection --
// ssh's ControlMaster -- has left as surely as one that hangs up.
func TestExecGuestClosingItsChannelHangsUpItsCommand(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})
	pidFile := filepath.Join(t.TempDir(), "pid")

	client := h.guestClient(t)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("sleep 60 & echo $! > "+pidFile+"; wait"))
	child := readPid(t, pidFile)

	require.NoError(t, sess.Close())
	requireGone(t, child, harnessTimeout)

	// And the connection still serves the next command.
	stdout, _, err := execGuest(t, client, "echo again")
	require.NoError(t, err)
	require.Equal(t, "again\n", stdout)
}

// A session that ends hangs up its guests' commands, and its end waits for
// them, so their guests are each sent a status before the session is gone.
func TestExecSessionEndHangsUpCommandsAndSendsAStatus(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})
	pidFile := filepath.Join(t.TempDir(), "pid")

	sess, err := h.guestClient(t).NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("sleep 60 & echo $! > "+pidFile+"; wait"))
	child := readPid(t, pidFile)

	waited := make(chan error, 1)
	go func() { waited <- sess.Wait() }()
	h.stop(t)

	select {
	case err := <-waited:
		var exit *ssh.ExitError
		require.ErrorAs(t, err, &exit, "the guest was sent no exit status: %v", err)
	case <-time.After(harnessTimeout):
		t.Fatal("the guest was never sent a status")
	}
	requireGone(t, child, harnessTimeout)
}

// A guest's command is its SSH session, described as sshd describes one: the
// host's own SSH session variables are not passed on.
func TestExecDoesNotPassOnTheHostsSSHSessionVars(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	t.Setenv("SSH_TTY", "/dev/pts/host")
	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowExec: true})

	stdout, _, err := execGuest(t, h.guestClient(t), `echo "tty=${SSH_TTY-unset}"`)
	require.NoError(t, err)
	require.Equal(t, "tty=unset\n", stdout)
}
