package hostnet

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The lock is held across setup, repair and cleanup. Separate network
// namespaces have independent tables/sysctls and therefore independent locks.
// Never unlink the file: contenders must all lock the same inode. The kernel
// releases flock on process exit, including crashes.
func acquireNetworkOwner(dir string) (*os.File, error) {
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return nil, fmt.Errorf("identifying network namespace: %w", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("creating network ownership directory %s: %w", dir, err)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening network ownership directory: %w", err)
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return nil, fmt.Errorf("network ownership directory must be owned by uid %d and not writable by others", os.Geteuid())
	}
	name := fmt.Sprintf("network-%d.lock", ns.Ino)
	fd, err := unix.Openat(dfd, name, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening network ownership lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, error) { _ = file.Close(); return nil, err }
	if err := unix.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return fail(fmt.Errorf("unsafe network ownership lock %s", name))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("another caddy-masque manager owns this network namespace (or the lock is unavailable): %w", err))
	}
	return file, nil
}
