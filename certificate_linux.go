package mTLS

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
)

func ListCertificates(certStoreName string) ([]string, error) {
	var certNames []string

	keys, err := os.ReadDir("/etc/pki/private")
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.certificate != nil {
		return s.certificate, nil
	}

	certFile := filepath.Join("/etc/pki/certs", s.CommonName+".crt")
	keyFile := filepath.Join("/etc/pki/private", s.CommonName+".key")

	// Načtení certifikátu a klíče
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	s.certificate = &cert

	return s.certificate, nil
}
