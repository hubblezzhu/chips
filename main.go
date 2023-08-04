//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"modules/func_stack"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-g -Wall -O2  --target=bpf -fPIC -D_FORTIFY_SOURCE=2 -ftrapv" bpf ../../bpf/stack.bpf.c -- -I/usr/include/bpf -I../../bpf

const mapKey uint32 = 0


func init() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat:"2006-01-02 15:04:05",  // time format
		FullTimestamp:true,
	})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.InfoLevel)
}

func main() {

	if err := func_stack.loadStackBpfProg(); err != nil {
		log.Error(fmt.Sprintf("load bpf objects: %w", err))
	}

	log.Info("load bpf objects success.")

	// mytest.test()
}
