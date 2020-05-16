package aescrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math"
)

// Errors might be returned. They will be wrapped with stacktrace at least, of course.
var (
	// Panic was recovered. Will be wrapped with actual panic message.
	ErrRecovered = errors.New("recovered")

	// Data provided are invalid. Will be wrapped with actual error message.
	ErrInvalidInput = errors.New("invalid input")
)

// DecryptAESCBCPadded will decrypt your data and trim the padding.
func DecryptAESCBCPadded(src, key, iv []byte) ([]byte, error) {
	dst, err := DecryptAESCBC(src, key, iv)
	if err != nil {
		return dst, err
	}
	return Pkcs7Unpad(dst, aes.BlockSize)
}

// DecryptAESCBC will decrypt your data.
func DecryptAESCBC(src, key, iv []byte) (dst []byte, err error) {
	defer catch(&err)

	dst = make([]byte, len(src))

	cip, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher.NewCBCDecrypter(cip, iv).CryptBlocks(dst, src)

	return dst, nil
}

// EncryptAESCBCPadded will pad your data and encrypt them.
func EncryptAESCBCPadded(src, key, iv []byte) ([]byte, error) {
	src, err := Pkcs7Pad(src, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return EncryptAESCBC(src, key, iv)
}

// EncryptAESCBC will encrypt your data.
func EncryptAESCBC(src, key, iv []byte) ([]byte, error) {
	dst := make([]byte, len(src))

	cip, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	c := cipher.NewCBCEncrypter(cip, iv)
	c.CryptBlocks(dst, src)

	return dst, nil
}

// Pkcs7Pad will pad your data.
func Pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 || blocklen > math.MaxUint8 {
		return nil, fmt.Errorf("invalid blocklen %d: %w", blocklen, ErrInvalidInput)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen++
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Pkcs7Unpad will trim the padding from your data.
func Pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 || blocklen > math.MaxUint8 {
		return nil, fmt.Errorf("invalid blocklen %d: %w", blocklen, ErrInvalidInput)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d: %w", len(data), ErrInvalidInput)
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding for %d bytes: %d > %d or %d == 0: %w", len(data), padlen, blocklen, padlen, ErrInvalidInput)
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding: %w", ErrInvalidInput)
		}
	}

	return data[:len(data)-padlen], nil
}

func catch(err *error) {
	e := recover()
	if e != nil {
		if errInternal, ok := e.(error); ok {
			*err = errInternal
		} else {
			*err = fmt.Errorf("%v: %w", e, ErrRecovered)
		}
	}
}
