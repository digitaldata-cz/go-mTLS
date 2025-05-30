package mTLS

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
)

var (
	certificateCache *tls.Certificate
)

func ListCertificates(certStoreName string) ([]string, error) {
	var certNames []string

	keys, err := os.ReadDir("/usr/local/etc/ssl/private")
	if err != nil {
		return certNames, err
	}

	for _, key := range keys {
		if filepath.Ext(key.Name()) != ".key" {
			continue
		}
		s := strings.TrimSuffix(key.Name(), filepath.Ext(key.Name()))
		certNames = append(certNames, s)
	}

	return certNames, nil
}

func (s *SystemSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if certificateCache != nil {
		return certificateCache, nil
	}

	certFile := filepath.Join("/usr/local/etc/ssl/certs", s.CommonName+".crt")
	keyFile := filepath.Join("/usr/local/etc/ssl/private", s.CommonName+".key")

	// Načtení certifikátu a klíče
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	certificateCache = &cert

	return certificateCache, nil
}
