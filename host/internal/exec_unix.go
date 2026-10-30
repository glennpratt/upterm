//go:build !windows

package internal

import (
	"log/slog"
	"os/exec"
	"syscall"
	"time"
)

// setExecProcessGroup starts a guest's exec command as the leader of a process
// group of its own, so that hanging it up reaches everything it started: a
// pipeline, a backgrounded child.
func setExecProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateExec hangs up a guest's exec command whose guest has left or whose
// session is ending, as terminateWith does a forced command, minus the pty:
// SIGHUP to its group, then SIGTERM, then SIGKILL, each followed by a wait
// that ends as soon as the command has. The command has no terminal to put
// back, but the hangup still comes first, so that what handles it can clean
// up after itself.
func terminateExec(cmd *exec.Cmd, exited <-chan struct{}, hangup, grace time.Duration, logger *slog.Logger, name string) {
	pgid := cmd.Process.Pid
	steps := []struct {
		sig  syscall.Signal
		wait time.Duration
	}{
		{syscall.SIGHUP, hangup},
		{syscall.SIGTERM, grace},
		{syscall.SIGKILL, grace},
	}
	for _, step := range steps {
		select {
		case <-exited:
			// Signalling the group now could reach a reused pid.
			return
		default:
		}
		_ = syscall.Kill(-pgid, step.sig)
		if waitExited(exited, step.wait) {
			return
		}
	}
	logger.Warn("guest exec command did not exit after being killed; giving up on this teardown", "command", name, "bound", grace)
}
