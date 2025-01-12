package mTLS

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
)

func ListCertificates(certStoreName string) ([]string, error) {
	var certNames []string

	keys, err := os.ReadDir("/etc/ssl/private")
	if err != nil {
		return certNames, err
	}

	for _, key := range keys {
		if filepath.Ext(key.Name()) != ".key" {
			continue
		}
		if _, err := os.Stat(filepath.Join("/etc/ssl/certs", strings.TrimSuffix(key.Name(), ".key")+".crt")); err != nil {
			continue
		}
		s := strings.TrimSuffix(key.Name(), filepath.Ext(key.Name()))
		certNames = append(certNames, s)
	}

	return certNames, nil
}

func (s *SystemSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	certFile := filepath.Join("/etc/ssl/certs", s.CommonName+".crt")
	keyFile := filepath.Join("/etc/ssl/private", s.CommonName+".key")

	b, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}

	b, err = os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}

	certificate := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	return certificate, nil
}
