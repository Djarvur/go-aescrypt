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
	testEncryptDecrypt(t, 16)
}

func TestPkcs7Pad(t *testing.T) {

}

func TestPkcs7Unpad(t *testing.T) {

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
