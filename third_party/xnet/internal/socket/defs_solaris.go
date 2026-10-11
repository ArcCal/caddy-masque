//go:build ignore

package socket

/*
#include <sys/socket.h>

#include <netinet/in.h>
*/
import "C"

type iovec C.struct_iovec

type msghdr C.struct_msghdr

type cmsghdr C.struct_cmsghdr

const (
	sizeofIovec  = C.sizeof_struct_iovec
	sizeofMsghdr = C.sizeof_struct_msghdr
)
