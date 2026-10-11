//go:build ignore

package socket

/*
#include <linux/in.h>
#include <linux/in6.h>

#define _GNU_SOURCE
#include <sys/socket.h>
*/
import "C"

type iovec C.struct_iovec

type msghdr C.struct_msghdr

type mmsghdr C.struct_mmsghdr

type cmsghdr C.struct_cmsghdr

const (
	sizeofIovec  = C.sizeof_struct_iovec
	sizeofMsghdr = C.sizeof_struct_msghdr
)
