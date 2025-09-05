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

func TestStringToCFStringEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("stringToCFString panicked: %v", r)
		}
	}()

	cfStr := stringToCFString("")
	if got := CFStringToString(cfStr); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
	C.CFRelease(C.CFTypeRef(cfStr))
}

func TestSignErrorMemory(t *testing.T) {
	signer := &CustomSigner{x509Cert: &x509.Certificate{}, privateKey: 0}
	digest := make([]byte, 32)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < 1000; i++ {
		if _, err := signer.Sign(nil, digest, crypto.SHA256); err == nil {
			t.Fatalf("expected error")
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	if delta := m2.Alloc - m1.Alloc; delta > 1<<20 {
		t.Fatalf("memory grew by %d bytes", delta)
	}
}
