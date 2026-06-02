// Package ebpf provides a stub for non-Linux platforms (macOS, Windows).
// The actual eBPF implementation is gated by the Linux build tag.
//
// On non-Linux systems, Monitor() returns a no-op channel and a warning log message.
// This allows the rest of the codebase to compile and run in development mode.

//go:build !linux
// +build !linux

package ebpf

import (
	"context"
	"log"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
)

// Monitor is a no-op stub for non-Linux platforms.
// The real eBPF monitor requires Linux kernel 5.8+ with BTF support.
func Monitor(ctx context.Context, clusterName string) (<-chan report.SecurityFinding, error) {
	log.Println("[ebpf] WARNING: eBPF runtime monitoring is not available on this platform (requires Linux 5.8+ with BTF).")
	log.Println("[ebpf] Running in simulation mode — no real events will be captured.")

	ch := make(chan report.SecurityFinding)

	// Return immediately closed channel (no events on non-Linux)
	go func() {
		<-ctx.Done()
		close(ch)
	}()

	return ch, nil
}
