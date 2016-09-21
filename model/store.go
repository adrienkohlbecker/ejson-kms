package model

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/adrienkohlbecker/errors"
)

// Store represents a credentials file.
type Store struct {
	// KMSKeyID is an aws ID pointing to the master key used to encrypt the
	// credentials in this file.
	//
	// This value can be a globally
	// unique identifier, a fully specified ID to either an alias or a key, or
	// an alias name prefixed by "alias/".
	//
	//   Key ARN Example - arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
	//
	//   Alias ARN Example - arn:aws:kms:us-east-1:123456789012:alias/MyAliasName
	//
	//   Globally Unique Key ID Example - 12345678-1234-1234-1234-123456789012
	//
	//   Alias Name Example - alias/MyAliasName
	KMSKeyID string `json:"kms_key_id"`

	// Version is the version of the JSON schema to use. For now there is only
	// version 1.
	Version int `json:"version"`

	// Name/value pair that contains additional data to be authenticated during
	// the encryption and decryption processes that use the key. This value is logged
	// by AWS CloudTrail to provide context around the data encrypted by the key.
	//
	// Note that changing this value requires re-encrypting every credential
	// in the file, since KMS uses it as part of the decryption process.
	EncryptionContext map[string]*string `json:"encryption_context"`

	// Credentials is a list of credentials
	Credentials []Credential `json:"credentials"`
}

// Import takes a path to a credentials file and returns the contents of the
// file unmarshaled in the model.
func Import(path string) (*Store, errors.Error) {

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to read file at %s", path), 0)
	}

	j := &Store{}
	err = json.Unmarshal(bytes, j)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to decode Store at %s", path), 0)
	}

	return j, nil

}

// Contains is a convenience wrapper to check for the existence of a given
// credential in the file.
func (j *Store) Contains(name string) bool {

	for _, item := range j.Credentials {
		if item.Name == name {
			return true
		}
	}

	return false

}

// Export takes a Store struct and writes it to disk to the given path.
// The Store is pretty-printed and file permissions are set to 0644.
func (j *Store) Export(path string) errors.Error {

	bytes, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		// Note: not covered by tests as no error can be hit with the current schema
		return errors.WrapPrefix(err, "Unable to marshall Store", 0)
	}

	bytes = append(bytes, []byte("\n")...)

	err = ioutil.WriteFile(path, bytes, 0644)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to write file at path %s", path), 0)
	}

	return nil

}
