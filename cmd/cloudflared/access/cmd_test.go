package access

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndRemoveAccessPidFile(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "cloudflared.pid")

	writeAccessPidFile(pidPath, &zerolog.Logger{})
	data, err := os.ReadFile(pidPath)
	require.NoError(t, err)

	pid, err := strconv.Atoi(string(data))
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), pid)

	removeAccessPidFile(pidPath, &zerolog.Logger{})
	_, err = os.Stat(pidPath)
	assert.True(t, os.IsNotExist(err), "pidfile should be removed after the forwarder exits")
}

func TestRemoveAccessPidFileMissingIsNoop(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "does-not-exist.pid")

	// Removing a non-existent pidfile must not log a fatal error or panic.
	removeAccessPidFile(pidPath, &zerolog.Logger{})
}
