// +build cgo

package openssl

/*
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/dh.h>

static long SSL_CTX_set_tmp_dh_not_a_macro(SSL_CTX* ctx, DH *dh) {
    return SSL_CTX_set_tmp_dh(ctx, dh);
}
static long PEM_read_DHparams_not_a_macro(SSL_CTX* ctx, DH *dh) {
    return SSL_CTX_set_tmp_dh(ctx, dh);
}
int BN_num_bytes_not_a_macro(const BIGNUM *a) {
	return BN_num_bytes(a);
}
int DH_size_not_a_macro(const DH *a) {
	return DH_size(a);
}

*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/tvdw/cgolock"
)

type DH struct {
	dh *C.struct_dh_st
}

// LoadDHParametersFromPEM loads the Diffie-Hellman parameters from
// a PEM-encoded block.
func LoadDHParametersFromPEM(pem_block []byte) (*DH, error) {
	cgolock.Lock()
	defer cgolock.Unlock()

	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	params := C.PEM_read_bio_DHparams(bio, nil, nil, nil)
	if params == nil {
		return nil, errors.New("failed reading dh parameters")
	}
	dhparams := &DH{dh: params}
	runtime.SetFinalizer(dhparams, func(dhparams *DH) {
		C.DH_free(dhparams.dh)
	})
	return dhparams, nil
}

// SetDHParameters sets the DH group (DH parameters) used to
// negotiate an emphemeral DH key during handshaking.
func (c *Ctx) SetDHParameters(dh *DH) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cgolock.Lock()
	defer cgolock.Unlock()

	if int(C.SSL_CTX_set_tmp_dh_not_a_macro(c.ctx, dh.dh)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

func LoadDHFromBignumWithGenerator(bytes []byte, generator int) (*DH, error) {
	cgolock.Lock()
	defer cgolock.Unlock()

	if len(bytes) == 0 {
		return nil, errors.New("empty block")
	}
	cdh := C.DH_new()
	if cdh == nil {
		return nil, errors.New("couldn't allocate a *DH")
	}

	dh := &DH{dh: cdh}
	runtime.SetFinalizer(dh, func(dhparams *DH) {
		C.DH_free(dhparams.dh)
	})

	gen := C.BN_new()
	if gen == nil {
		return nil, errors.New("something went wrong in openssl")
	}
	C.BN_set_word(gen, C.ulong(generator))

	bn := C.BN_bin2bn((*C.uchar)(&bytes[0]), C.int(len(bytes)), nil)
	if bn == nil {
		C.BN_free(gen)
		return nil, errors.New("failed to load the key into memory")
	}

	dh.dh.g = gen
	dh.dh.p = bn
	dh.dh.length = 320

	if C.DH_generate_key(dh.dh) == 0 {
		return nil, errors.New("Failed to generate a DH key")
	}

	return dh, nil
}

func (dh *DH) GetPublicKey() ([]byte, error) {
	cgolock.Lock()
	defer cgolock.Unlock()

	bytes := C.BN_num_bytes_not_a_macro(dh.dh.pub_key)
	dat := make([]byte, bytes)
	C.BN_bn2bin(dh.dh.pub_key, (*C.uchar)(&dat[0]))
	return dat, nil
}

func (dh *DH) GetSharedKey(challenge []byte) ([]byte, error) {
	cgolock.Lock()
	defer cgolock.Unlock()

	bn := C.BN_bin2bn((*C.uchar)(&challenge[0]), C.int(len(challenge)), nil)
	dat := make([]byte, C.DH_size_not_a_macro(dh.dh))

	C.DH_compute_key((*C.uchar)(&dat[0]), bn, dh.dh)

	return dat, nil
}
