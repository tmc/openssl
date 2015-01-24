// +build cgo

package openssl

// #include <openssl/evp.h>
// #include <openssl/rsa.h>
import "C"

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/tvdw/cgolock"
)

func (key *pKey) Decrypt(source []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cgolock.Lock()
	defer cgolock.Unlock()

	if len(source) == 0 {
		return nil, errors.New("no data to encrypt")
	}

	rsa := C.EVP_PKEY_get1_RSA(key.key)
	if rsa == nil {
		return nil, errors.New("given key is not an RSA key")
	}

	returnSize := int(C.RSA_size(rsa))
	buf := make([]byte, returnSize)

	rt := int(C.RSA_private_decrypt(C.int(len(source)), (*C.uchar)(unsafe.Pointer(&source[0])), (*C.uchar)(unsafe.Pointer(&buf[0])), rsa, C.RSA_PKCS1_OAEP_PADDING))
	if rt < 0 {
		return nil, errorFromErrorQueue()
	}

	buf = buf[:rt]
	return buf, nil
}
