package aescrypt_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/Djarvur/go-aescrypt"
)

func TestEncryptDecrypt128(t *testing.T) {
	testEncryptDecrypt(t, 16)
}

func TestEncryptDecrypt256(t *testing.T) {
	testEncryptDecrypt(t, 32)
}

func TestPkcs7PadNegate(t *testing.T) {
	_, err := aescrypt.Pkcs7Pad(make([]byte, 12), 0)
	if err == nil {
		t.Error("bad blocklen allowed")
	}

	_, err = aescrypt.Pkcs7Pad(make([]byte, 12), 1024)
	if err == nil {
		t.Error("bad blocklen allowed")
	}
}

func TestPkcs7UnpadNegate(t *testing.T) {
	_, err := aescrypt.Pkcs7Unpad(make([]byte, aes.BlockSize), 0)
	if err == nil {
		t.Error("bad blocklen allowed")
	}

	_, err = aescrypt.Pkcs7Unpad(make([]byte, aes.BlockSize), 1024)
	if err == nil {
		t.Error("bad blocklen allowed")
	}

	_, err = aescrypt.Pkcs7Unpad(make([]byte, 12), aes.BlockSize)
	if err == nil {
		t.Error("bad data size allowed")
	}

	_, err = aescrypt.Pkcs7Unpad(make([]byte, aes.BlockSize), aes.BlockSize)
	if err == nil {
		t.Error("bad data allowed")
	}

	data, err := aescrypt.Pkcs7Pad(make([]byte, 12), aes.BlockSize)
	if err != nil {
		t.Fatal("unexpected Pkcs7Pad error", err)
	}

	data[len(data)-2] -= 1

	_, err = aescrypt.Pkcs7Unpad(data, aes.BlockSize)
	if err == nil {
		t.Error("bad padding allowed")
	}
}

func testEncryptDecrypt(t *testing.T, keyLen int) {
	var (
		data = randBytes(37)
		key  = randBytes(keyLen)
		iv   = randBytes(aes.BlockSize)
	)

	encData, err := aescrypt.EncryptAESCBCpad(data, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	decData, err := aescrypt.DecryptAESCBCunpad(encData, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decData) {
		t.Error("decrypted data is not equal to original")
	}
}
