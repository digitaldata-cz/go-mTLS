//go:build windows

package mtlssigner

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ListCertificates(certStoreName string) ([]string, error) {
	// Open the certificate store
	var certStore uint32
	switch certStoreName {
	case CertStoreNameLocalMachine:
		certStore = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	case CertStoreNameCurrentUser:
		certStore = windows.CERT_SYSTEM_STORE_CURRENT_USER
	default:
		return nil, fmt.Errorf("unsupported certificate store")
	}
	//fmt.Println("DEBUG: Opening cert store", certStoreName)
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		certStore|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_SHARE_CONTEXT_FLAG,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("MY"))),
	)
	if err != nil {
		//fmt.Println("DEBUG: chyba", err)
		return nil, err
	}
	//fmt.Println("DEBUG: Cert store opened")
	defer windows.CertCloseStore(store, 0)

	// Find the certificate
	var pPrevCertContext *windows.CertContext
	var certContext *windows.CertContext
	var certNames []string
	for {
		//fmt.Println("DEBUG: Looking for cert")
		certContext, err = windows.CertFindCertificateInStore(
			store,
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
			0,
			windows.CERT_FIND_HAS_PRIVATE_KEY,
			nil,
			pPrevCertContext,
		)
		if err != nil {
			//fmt.Println("DEBUG: Cert not found:", err.Error())
			break
		}
		pPrevCertContext = certContext
		certRaw := unsafe.Slice(certContext.EncodedCert, certContext.Length)
		//fmt.Println("DEBUG: Cert found - parsing")
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			//fmt.Println("DEBUG: Cert not parsed:", err.Error())
			continue
		}
		//fmt.Println("DEBUG: Cert parsed")
		if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
			//fmt.Println("DEBUG: Cert not valid", cert.Subject.CommonName)
			continue
		}
		//fmt.Println("DEBUG: Cert valid - adding to list", cert.Subject.CommonName)
		certNames = append(certNames, cert.Subject.CommonName)
	}
	//fmt.Println("DEBUG: Returning cert names")
	//defer windows.CertFreeCertificateContext(pPrevCertContext)
	return certNames, nil
}

func (s *SystemSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	// Validate the supported signature schemes.
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	signatureSchemeSupported := false
	for i := range info.SignatureSchemes {
		//fmt.Println("DEBUG: Requested signature scheme -", info.SignatureSchemes[i].String())
		if info.SignatureSchemes[i] == tls.PSSWithSHA256 ||
			info.SignatureSchemes[i] == tls.PSSWithSHA384 ||
			info.SignatureSchemes[i] == tls.PSSWithSHA512 {
			signatureSchemeSupported = true
			break
		}
	}
	if !signatureSchemeSupported {
		return nil, fmt.Errorf("unsupported signature scheme")
	}

	// Open the certificate store
	//fmt.Println("DEBUG: Opening cert store", s.CertStoreName)
	var certStore uint32
	switch s.CertStoreName {
	case CertStoreNameLocalMachine:
		certStore = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	case CertStoreNameCurrentUser:
		certStore = windows.CERT_SYSTEM_STORE_CURRENT_USER
	default:
		return nil, fmt.Errorf("unsupported certificate store")
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		certStore|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_SHARE_CONTEXT_FLAG,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("MY"))),
	)
	if err != nil {
		//fmt.Println("DEBUG: chyba", err)
		return nil, err
	}

	// Find the certificate
	var pPrevCertContext *windows.CertContext
	var certContext *windows.CertContext
	// TODO: Loop through all certificates in the store and find the one with the correct time validity
	//fmt.Println("DEBUG: Looking for cert with common name", s.CommonName)
	certFound := false
	for {
		//fmt.Println("DEBUG: Looking for cert")
		certContext, err = windows.CertFindCertificateInStore(
			store,
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
			0,
			windows.CERT_FIND_HAS_PRIVATE_KEY,
			nil,
			pPrevCertContext,
		)
		if err != nil {
			break
		}
		pPrevCertContext = certContext
		certRaw := unsafe.Slice(certContext.EncodedCert, certContext.Length)
		//fmt.Println("DEBUG: Found certificate - parsing")
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			//fmt.Println("DEBUG: Certificate not parsed:", err.Error())
			continue
		}
		//fmt.Println("DEBUG: Certificate parsed")
		if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
			//fmt.Println("DEBUG: Certificate not valid", cert.Subject.CommonName)
			continue
		}
		//fmt.Println("DEBUG: Found certificate with common name", cert.Subject.CommonName)
		if cert.Subject.CommonName == s.CommonName {
			certFound = true
			//fmt.Println("DEBUG: Certificate found!!!")
			break
		}
	}
	if !certFound {
		return nil, fmt.Errorf("certificate not found")
	}
	//fmt.Println("DEBUG: Cert found")

	customSigner := &windowSigner{
		store:              store,
		windowsCertContext: certContext,
	}

	// Set a finalizer to release Windows resources when the CustomSigner is garbage collected.
	runtime.SetFinalizer(
		customSigner, func(c *windowSigner) {
			_ = windows.CertFreeCertificateContext(c.windowsCertContext)
			_ = windows.CertCloseStore(c.store, 0)
		},
	)

	// Copy the certificate data so that we have our own copy outside the windows context
	encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	buf := bytes.Clone(encodedCert)
	foundCert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}

	customSigner.x509Cert = foundCert

	certificate := tls.Certificate{
		Certificate:                  [][]byte{foundCert.Raw},
		PrivateKey:                   customSigner,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512},
	}
	//fmt.Printf("Found certificate with common name %s\n", foundCert.Subject.CommonName)
	return &certificate, nil
}
