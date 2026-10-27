package evidence

import (
	"errors"
	"io/fs"
	"syscall"
)

// isDirSyncUnsupported reports whether a directory fsync failed because the
// platform cannot flush a directory handle. Windows returns ERROR_ACCESS_DENIED
// for FlushFileBuffers on a directory; some network filesystems return EINVAL or
// ENOTSUP. In all of those cases the rename already made the file visible, so the
// caller should not treat the scan as failed.
func isDirSyncUnsupported(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EINVAL, syscall.ENOTSUP, syscall.EPERM, syscall.EACCES:
			return true
		}
	}
	// Windows wraps the OS error; match the generic permission/unsupported paths.
	return errors.Is(err, fs.ErrPermission)
}
