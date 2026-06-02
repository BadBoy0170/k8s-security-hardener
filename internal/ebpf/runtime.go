//go:build linux
// +build linux

// Package ebpf provides runtime container execution monitoring using Linux eBPF.
// This package ONLY compiles and runs on Linux kernel 5.8+ with BTF support.
// On macOS/Windows, use the stub version (runtime_stub.go).
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// execEvent mirrors the C struct sent from the eBPF program via ringbuf.
// Must match the BPF struct layout exactly.
type execEvent struct {
	PID         uint32
	TGID        uint32
	ContainerID [64]byte
	Comm        [16]byte  // process name (comm)
	Filename    [256]byte // full path of executed binary
}

// SuspiciousExecNames are binaries that should not normally run in web/app containers.
var SuspiciousExecNames = map[string]bool{
	"curl":          true,
	"wget":          true,
	"bash":          true,
	"sh":            true,
	"python":        true,
	"python3":       true,
	"perl":          true,
	"ncat":          true,
	"nc":            true,
	"netcat":        true,
	"socat":         true,
	"/bin/bash":     true,
	"/bin/sh":       true,
	"/usr/bin/curl": true,
}

// Monitor attaches to the sys_enter_execve tracepoint and watches for
// suspicious process executions inside containers.
// Findings are emitted to the returned channel and the monitor runs until ctx is cancelled.
func Monitor(ctx context.Context, clusterName string) (<-chan report.SecurityFinding, error) {
	// Remove memory lock limits (required for eBPF map allocation)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled eBPF objects from embedded bytes
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Attach to the execve tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach tracepoint: %w", err)
	}

	// Open ringbuf reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to open ringbuf: %w", err)
	}

	findings := make(chan report.SecurityFinding, 100)

	go func() {
		defer close(findings)
		defer rd.Close()
		defer tp.Close()
		defer objs.Close()

		log.Println("[ebpf] Runtime monitor started — watching sys_enter_execve")

		for {
			select {
			case <-ctx.Done():
				log.Println("[ebpf] Runtime monitor shutting down")
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[ebpf] ringbuf read error: %v", err)
				continue
			}

			var event execEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("[ebpf] failed to decode event: %v", err)
				continue
			}

			comm := nullTermString(event.Comm[:])
			filename := nullTermString(event.Filename[:])
			containerID := nullTermString(event.ContainerID[:])

			if !SuspiciousExecNames[comm] && !SuspiciousExecNames[filename] {
				continue
			}

			log.Printf("[ebpf] ALERT: suspicious exec detected — pid=%d comm=%s file=%s container=%s",
				event.PID, comm, filename, containerID)

			findings <- report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityCritical,
				RuleID:      "EBPF-001",
				ClusterName: clusterName,
				Namespace:   "runtime",
				Resource:    fmt.Sprintf("container/%s (pid %d)", containerID, event.PID),
				Description: fmt.Sprintf("Suspicious binary execution detected inside container: '%s' (comm: %s) — potential reverse shell or lateral movement", filename, comm),
				Remediation: "Isolate the pod immediately. Review container image and recent deployments. Check for supply chain compromise.",
			}
		}
	}()

	return findings, nil
}

// nullTermString converts a null-terminated byte slice to a Go string.
func nullTermString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

// Ensure unsafe is used (required for ebpf map pointer alignment).
var _ = unsafe.Sizeof(0)
var _ = os.DevNull
