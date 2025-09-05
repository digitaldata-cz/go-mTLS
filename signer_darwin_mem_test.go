//go:build darwin && cgo

package mTLS

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"crypto"
	"crypto/x509"
	"runtime"
	"testing"
)

// TestSignErrorDoesNotLeakMemory ensures that repeated signing errors do not
// grow memory usage, indicating proper release of CoreFoundation objects.
func TestSignErrorDoesNotLeakMemory(t *testing.T) {
	signer := &CustomSigner{x509Cert: &x509.Certificate{}, privateKey: 0}
	digest := make([]byte, 32)

	runtime.GC()
	var mStart, mEnd runtime.MemStats
	runtime.ReadMemStats(&mStart)

	for i := 0; i < 1000; i++ {
		if _, err := signer.Sign(nil, digest, crypto.SHA256); err == nil {
			t.Fatalf("expected signing error")
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&mEnd)
	if diff := int64(mEnd.Alloc) - int64(mStart.Alloc); diff > 1<<20 {
		t.Fatalf("memory allocation increased by %d bytes", diff)
	}
}
