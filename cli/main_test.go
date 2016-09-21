package cli

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/adrienkohlbecker/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testDataEmpty         = "./testdata/empty.json"
	testDataInvalid       = "./testdata/invalid.json"
	testDataOneCredential = "./testdata/one_credential.json"

	testKmsKeyID       = "arn:aws:kms:eu-west-1:012345678912:alias/ejson-kms-testing"
	testKeyPlaintext   = "-abcdefabcdefabcdefabcdefabcdef-"
	testKeyCiphertext  = "ciphertextblob"
	testKmsKeyID2      = "arn:aws:kms:eu-west-1:012345678912:alias/ejson-kms-testing-other"
	testKeyPlaintext2  = "-012345678901234567890123456789-"
	testKeyCiphertext2 = "anotherciphertextblob"
)

func withTempPath(t *testing.T, f func(storePath string)) {

	out, err := ioutil.TempFile(os.TempDir(), "ejson-kms-tests")
	assert.NoError(t, err)

	err = out.Close()
	assert.NoError(t, err)

	err = os.Remove(out.Name())
	assert.NoError(t, err)

	f(out.Name())

}

func withTempStore(t *testing.T, testdata string, f func(storePath string)) {

	storePath, err := copyFileToTemp(testdata)
	assert.NoError(t, err)

	f(storePath)

	err = os.Remove(storePath)
	assert.NoError(t, err)

}

func copyFileToTemp(src string) (string, error) {

	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() {
		cerr := in.Close()
		if cerr != nil {
			fmt.Printf("error while closing in: %s", cerr)
		}
	}()

	out, err := ioutil.TempFile(os.TempDir(), "ejson-kms-tests")
	if err != nil {
		return "", err
	}
	defer func() {
		cerr := out.Close()
		if cerr != nil {
			fmt.Printf("error while closing out: %s", cerr)
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return "", err
	}

	err = out.Sync()
	if err != nil {
		return "", err
	}

	return out.Name(), nil
}

func withStdin(t *testing.T, str string, f func()) {

	tmpfile, err := ioutil.TempFile(os.TempDir(), "read-from-file")
	assert.NoError(t, err)

	_, err = tmpfile.WriteString(str)
	assert.NoError(t, err)
	err = tmpfile.Sync()
	assert.NoError(t, err)
	_, err = tmpfile.Seek(0, 0)
	assert.NoError(t, err)

	original := os.Stdin
	os.Stdin = tmpfile

	f()

	os.Stdin = original

	err = tmpfile.Close()
	assert.NoError(t, err)
	err = os.Remove(tmpfile.Name())
	assert.NoError(t, err)

}

func withStdinError(t *testing.T, f func()) {

	tmpfile, err := ioutil.TempFile(os.TempDir(), "read-from-file")
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	original := os.Stdin
	os.Stdin = tmpfile

	f()

	os.Stdin = original

	err = os.Remove(tmpfile.Name())
	assert.NoError(t, err)

}

func withKMSNewClientError(t *testing.T, f func()) {

	original := kmsNewClient
	kmsNewClient = func() (kms.Client, errors.Error) {
		return nil, errors.Errorf("testing errors")
	}

	f()

	kmsNewClient = original

}

func withMockKmsClient(t *testing.T, other kms.Client, f func()) {

	original := kmsNewClient
	kmsNewClient = func() (kms.Client, errors.Error) {
		return other, nil
	}

	f()

	kmsNewClient = original

}
