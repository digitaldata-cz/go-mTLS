package mTLS

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
}

type EmbeddedSigner struct {
	PKCS12   []byte
	Password string
}
