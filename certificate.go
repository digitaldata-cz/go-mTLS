package mTLS

import (
	"crypto/tls"

	"golang.org/x/crypto/pkcs12"
)

func (s *EmbeddedSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.once.Do(func() {
		key, cert, err := pkcs12.Decode(s.PKCS12, s.Password)
		if err != nil {
			s.err = err
			return
		}
		s.certificate = &tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}
	})
	return s.certificate, s.err
}
