//go:build darwin && cgo

package mTLS

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import "testing"

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
