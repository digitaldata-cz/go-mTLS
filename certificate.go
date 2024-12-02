package mTLS

import (
	"crypto/tls"

	"golang.org/x/crypto/pkcs12"
)

func (s *EmbeddedSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	TLSClientKey, TLSClientCert, err := pkcs12.Decode(s.PKCS12, s.Password)
	if err != nil {
		return nil, err
	}
	certificate := &tls.Certificate{
		Certificate: [][]byte{TLSClientCert.Raw},
		PrivateKey:  TLSClientKey,
	}
	return certificate, nil
}
