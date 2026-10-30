//go:build windows

package internal

import (
	"log/slog"
	"os/exec"
	"time"
)

// setExecProcessGroup does nothing on Windows, where the CLI refuses
// --allow-exec: a Windows host's shell takes no -c.
func setExecProcessGroup(cmd *exec.Cmd) {}

// terminateExec kills the command outright: Windows has no hangup to send.
func terminateExec(cmd *exec.Cmd, exited <-chan struct{}, hangup, grace time.Duration, logger *slog.Logger, name string) {
	_ = cmd.Process.Kill()
	if !waitExited(exited, grace) {
		logger.Warn("guest exec command did not exit after being killed; giving up on this teardown", "command", name, "bound", grace)
	}
}
