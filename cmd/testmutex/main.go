package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	k := syscall.NewLazyDLL("kernel32.dll")
	name, _ := syscall.UTF16PtrFromString(`Global\rupasd-single`)
	r1, _, err := k.NewProc("CreateMutexW").Call(0, 1, uintptr(unsafe.Pointer(name)))
	fmt.Println("handle:", r1 != 0, "errno:", err, "already:", err == syscall.ERROR_ALREADY_EXISTS)
	time.Sleep(20 * time.Second)
}
