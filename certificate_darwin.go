//go:build darwin && cgo

package mTLS

/*
   #cgo LDFLAGS: -framework CoreFoundation -framework Security
   #include <CoreFoundation/CoreFoundation.h>
   #include <Security/Security.h>
*/
import "C"
import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

func (s *SystemSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.certificate != nil {
		return s.certificate, nil
	}

	fmt.Printf("Server requested certificate\n")

	// Validate the supported signature schemes.
	signatureSchemeSupported := false
	for _, scheme := range info.SignatureSchemes {
		if scheme == supportedAlgorithm {
			signatureSchemeSupported = true
			break
		}
	}
	if !signatureSchemeSupported {
		return nil, fmt.Errorf("unsupported signature scheme")
	}

	// Find certificate using SecItemCopyMatching
	// https://developer.apple.com/documentation/security/1398306-secitemcopymatching
	identitySearch := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault, maxCertificatesNum, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks,
	)
	defer C.CFRelease(C.CFTypeRef(unsafe.Pointer(identitySearch)))
	var commonNameCFString = stringToCFString(s.CommonName)
	defer C.CFRelease(C.CFTypeRef(commonNameCFString))
	C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassIdentity))
	C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecAttrCanSign), unsafe.Pointer(C.kCFBooleanTrue))
	C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchSubjectWholeString), unsafe.Pointer(commonNameCFString))
	// To filter by issuers, we must provide a CFDataRef array of DER-encoded ASN.1 items.
	// C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchIssuers), unsafe.Pointer(issuerCFArray))
	C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))
	C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll))
	var identityMatches C.CFTypeRef
	if status := C.SecItemCopyMatching(C.CFDictionaryRef(identitySearch), &identityMatches); status != C.errSecSuccess {
		return nil, fmt.Errorf("failed to find client certificate: %v", status)
	}
	defer C.CFRelease(identityMatches)

	var foundCert *x509.Certificate
	var foundIdentity C.SecIdentityRef
	identityMatchesArrayRef := C.CFArrayRef(identityMatches)
	numIdentities := int(C.CFArrayGetCount(identityMatchesArrayRef))
	fmt.Printf("Found %d identities\n", numIdentities)
	for i := 0; i < numIdentities; i++ {
		identityMatch := C.CFArrayGetValueAtIndex(identityMatchesArrayRef, C.CFIndex(i))
		x509Cert, err := identityRefToCert(C.SecIdentityRef(identityMatch))
		if err != nil {
			continue
		}
		// Make sure certificate is not expired
		if x509Cert.NotAfter.After(time.Now()) {
			foundCert = x509Cert
			foundIdentity = C.SecIdentityRef(identityMatch)
			fmt.Printf("Found certificate from issuer %s with public key type %T\n", x509Cert.Issuer.String(), x509Cert.PublicKey)
			break
		}
	}

	if foundCert == nil {
		return nil, fmt.Errorf("failed to find a valid client certificate")
	}

	// Grab the private key reference (does not contain the private key cleartext).
	var privateKey C.SecKeyRef
	if status := C.SecIdentityCopyPrivateKey(C.SecIdentityRef(foundIdentity), &privateKey); status != 0 {
		return nil, fmt.Errorf("failed to copy private key ref from identity: %v", status)
	}

	customSigner := &CustomSigner{
		x509Cert:   foundCert,
		privateKey: privateKey,
	}
	// Set a finalizer to release the private key reference when the CustomSigner is garbage collected.
	runtime.SetFinalizer(
		customSigner, func(c *CustomSigner) {
			C.CFRelease(C.CFTypeRef(c.privateKey))
		},
	)
	certificate := &tls.Certificate{
		Certificate:                  [][]byte{foundCert.Raw},
		PrivateKey:                   customSigner,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
	}
	s.certificate = certificate
	return certificate, nil
}
