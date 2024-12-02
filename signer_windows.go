//go:build windows

package mTLS

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	nCrypt         = windows.MustLoadDLL("ncrypt.dll")
	nCryptSignHash = nCrypt.MustFindProc("NCryptSignHash")
)

// signer is a crypto.Signer that uses the client certificate and key to sign
type windowSigner struct {
	store              windows.Handle
	windowsCertContext *windows.CertContext
	x509Cert           *x509.Certificate
}

func (k *windowSigner) Public() crypto.PublicKey {
	return k.x509Cert.PublicKey
}

func (k *windowSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	// Validate the supported signature schemes.
	pssOpts, ok := opts.(*rsa.PSSOptions)
	if !ok {
		return nil, fmt.Errorf("unknown hash function %s", opts.HashFunc().String())
	}
	if pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash {
		return nil, fmt.Errorf("unsupported salt length %d", pssOpts.SaltLength)
	}

	const (
		nCryptSilentFlag = 0x00000040 // ncrypt.h NCRYPT_SILENT_FLAG
		bCryptPadPss     = 0x00000008 // bcrypt.h BCRYPT_PAD_PSS
	)

	// Get private key
	var (
		privateKey                  windows.Handle
		pdwKeySpec                  uint32
		pfCallerFreeProvOrNCryptKey bool
	)
	err = windows.CryptAcquireCertificatePrivateKey(
		k.windowsCertContext,
		windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil,
		&privateKey,
		&pdwKeySpec,
		&pfCallerFreeProvOrNCryptKey,
	)
	if err != nil {
		return nil, err
	}

	var hashAlg *uint16
	switch pssOpts.HashFunc() {
	case crypto.SHA256:
		hashAlg, _ = windows.UTF16PtrFromString("SHA256")
	case crypto.SHA384:
		hashAlg, _ = windows.UTF16PtrFromString("SHA384")
	case crypto.SHA512:
		hashAlg, _ = windows.UTF16PtrFromString("SHA512")
	default:
		return nil, fmt.Errorf("unsupported hash function %s", pssOpts.HashFunc().String())
	}

	// Create BCRYPT_PSS_PADDING_INFO structure:
	// typedef struct _BCRYPT_PSS_PADDING_INFO {
	// 	LPCWSTR pszAlgId;
	// 	ULONG   cbSalt;
	// } BCRYPT_PSS_PADDING_INFO;
	pPaddingInfo := unsafe.Pointer(
		&struct {
			pszAlgId *uint16
			cbSalt   uint32
		}{
			pszAlgId: hashAlg,
			cbSalt:   uint32(pssOpts.HashFunc().Size()),
		},
	)

	// Sign the digest
	// The first call to NCryptSignHash retrieves the size of the signature
	var size uint32
	success, _, _ := nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&size)),
		uintptr(nCryptSilentFlag|bCryptPadPss),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to get signature length: %#x", success)
	}

	// The second call to NCryptSignHash retrieves the signature
	signature = make([]byte, size)
	success, _, _ = nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(nCryptSilentFlag|bCryptPadPss),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to generate signature: %#x", success)
	}
	return signature, nil
}
