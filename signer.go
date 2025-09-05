package mTLS

import (
	"crypto/tls"
	"sync"
)

const (
	CertStoreNameFileP12      = "FILE_P12" // TODO implement
	CertStoreNameFilePEM      = "FILE_PEM" // TODO implement
	CertStoreNameFileDER      = "FILE_DER" // TODO implement
	CertStoreNameLocalMachine = "LOCAL_MACHINE"
	CertStoreNameCurrentUser  = "CURRENT_USER"
)

type SystemSigner struct {
	CertStoreName string
	CommonName    string

	mu          sync.Mutex
	certificate *tls.Certificate
}

type EmbeddedSigner struct {
	PKCS12   []byte
	Password string

	// once ensures the certificate is loaded and cached only once.
	once        sync.Once
	// certificate caches the loaded TLS certificate for repeated use.
	certificate *tls.Certificate
	// err stores any error encountered during certificate loading.
	err         error
}
