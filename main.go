package main

import (
    "bufio"
    "errors"
    "log"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG, $BPF_CFLAGS and $BPF_HEADERS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf demo.c -- -I$BPF_HEADERS

func main() {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

    uids := make([] uint32, len(os.Args) - 1)
    for i, uid := range os.Args[1:] {
        if uid64, err := strconv.ParseUint(uid, 10, 32); err != nil {
            log.Fatalf("invalid uid[%s]: %s", uid, err)
        } else {
            uids[i] = uint32(uid64)
        }
    }

    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    pinPath := "/sys/fs/bpf/demo"
    if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
        log.Fatalf("failed to create bpffs directory: %+v", err)
    }

    // Load pre-compiled programs and maps into the kernel.
    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, &ebpf.CollectionOptions {
        Maps: ebpf.MapOptions {
            PinPath: pinPath,
        },
    }); err != nil {
        log.Fatalf("loading objects: %s", err)
    }
    defer objs.Close()

    for _, uid := range uids {
        if err := objs.UidPermissionMap.Put(uid, uint8(0)); err != nil {
            log.Fatalf("%s", err)
        }
    }

    cgroupPath, err := detectCgroupPath()
    if err != nil {
        log.Fatal(err)
    }

    l, err := link.AttachCgroup(link.CgroupOptions{
        Path: cgroupPath,
        Attach: ebpf.AttachCGroupInetSockCreate,
        Program: objs.InetSocketCreate,
    })
    defer l.Close()

    log.Printf("Successfully started!")

    <- stopper
    objs.UidPermissionMap.Unpin()
    log.Println("Received signal, exiting program..")
}

func detectCgroupPath() (string, error) {
    f, err := os.Open("/proc/mounts")
    if err != nil {
        return "", err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        fields := strings.Split(scanner.Text(), " ")
        if len(fields) >= 3 && fields[2] == "cgroup2" {
            return fields[1], nil
        }
    }

    return "", errors.New("cgroup2 not mounted")
}
