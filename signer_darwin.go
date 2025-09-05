//go:build darwin && cgo

package mTLS

/*
   #cgo CFLAGS: -x objective-c
   #cgo LDFLAGS: -framework CoreFoundation -framework Security
   #include <CoreFoundation/CoreFoundation.h>
   #include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"unsafe"
)

const (
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	supportedAlgorithm = tls.PSSWithSHA256
	maxCertificatesNum = 10
)

// identityRefToCert converts a C.SecIdentityRef into an *x509.Certificate
func identityRefToCert(identityRef C.SecIdentityRef) (*x509.Certificate, error) {
	// Convert the identity to a certificate
	var certificateRef C.SecCertificateRef
	if status := C.SecIdentityCopyCertificate(identityRef, &certificateRef); status != 0 {
		return nil, fmt.Errorf("failed to get certificate from identity: %v", status)
	}
	defer C.CFRelease(C.CFTypeRef(certificateRef))

	// Export the certificate to PEM
	// SecItemExport: https://developer.apple.com/documentation/security/1394828-secitemexport
	var pemDataRef C.CFDataRef
	if status := C.SecItemExport(
		C.CFTypeRef(certificateRef), C.kSecFormatPEMSequence, C.kSecItemPemArmour, nil, &pemDataRef,
	); status != 0 {
		return nil, fmt.Errorf("failed to export certificate to PEM: %v", status)
	}
	defer C.CFRelease(C.CFTypeRef(pemDataRef))
	certPEM := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(pemDataRef)), C.int(C.CFDataGetLength(pemDataRef)))

	var x509Cert *x509.Certificate
	for block, rest := pem.Decode(certPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			var err error
			x509Cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing client certificate: %v", err)
			}
		}
	}
	return x509Cert, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	x509Cert   *x509.Certificate
	privateKey C.SecKeyRef
}

func (k *CustomSigner) Public() crypto.PublicKey {
	fmt.Printf("crypto.Signer.Public\n")
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())
	fmt.Println("DEBUG: Requested signature scheme -", opts.HashFunc().String())
	fmt.Println("DEBUG: Requested signature scheme -", supportedAlgorithm)

	// Convert the digest to a CFDataRef
	digestCFData := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	defer C.CFRelease(C.CFTypeRef(digestCFData))

	// SecKeyAlgorithm: https://developer.apple.com/documentation/security/seckeyalgorithm
	// SecKeyCreateSignature: https://developer.apple.com/documentation/security/1643916-seckeycreatesignature
	var cfErrorRef C.CFErrorRef
	signCFData := C.SecKeyCreateSignature(
		k.privateKey, C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256, C.CFDataRef(digestCFData), &cfErrorRef,
	)
	if cfErrorRef != 0 {
		cdescription := C.CFErrorCopyDescription(cfErrorRef)
		defer C.CFRelease(C.CFTypeRef(cdescription))
		C.CFRelease(C.CFTypeRef(cfErrorRef))
		fmt.Printf("DEBUG: %v", CFStringToString(cdescription))
		return nil, fmt.Errorf("failed to sign data: %v", CFStringToString(cdescription))
	}
	defer C.CFRelease(C.CFTypeRef(signCFData))

	// Convert CFDataRef to Go byte slice
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(signCFData)), C.int(C.CFDataGetLength(signCFData))), nil
}

// stringToCFString converts Go string to CFStringRef
func stringToCFString(s string) C.CFStringRef {
	bytes := []byte(s)
	if len(bytes) == 0 {
		return C.CFStringCreateWithBytes(
			C.kCFAllocatorDefault,
			nil,
			0,
			C.kCFStringEncodingUTF8,
			C.false,
		)
	}
	ptr := (*C.UInt8)(unsafe.Pointer(&bytes[0]))
	return C.CFStringCreateWithBytes(C.kCFAllocatorDefault, ptr, C.CFIndex(len(bytes)), C.kCFStringEncodingUTF8, C.false)
}

// CFStringToString converts CFStringRef to Go string
func CFStringToString(cfString C.CFStringRef) string {
	var buffer [8192]byte
	C.CFStringGetCString(cfString, (*C.char)(unsafe.Pointer(&buffer[0])), C.CFIndex(len(buffer)), C.kCFStringEncodingUTF8)
	return C.GoString((*C.char)(unsafe.Pointer(&buffer[0])))
}
