package model

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/adrienkohlbecker/ejson-kms/kms"
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
	Credentials []*Credential `json:"credentials"`
}

// NewStore returns a new empty store
func NewStore(kmsKeyID string, encryptionContext map[string]*string) *Store {

	return &Store{
		KMSKeyID:          kmsKeyID,
		Version:           1,
		EncryptionContext: encryptionContext,
		Credentials:       make([]*Credential, 0),
	}

}

// Load takes a path to a credentials file and returns the contents of the
// file unmarshaled in the model.
func Load(path string) (*Store, errors.Error) {

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
	return j.Find(name) != nil
}

// Save takes a Store struct and writes it to disk to the given path.
// The JSON is pretty-printed and file permissions are set to 0644.
func (j *Store) Save(path string) errors.Error {

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

// Add adds a new credential to the store
func (j *Store) Add(client kms.Client, plaintext string, name string, description string) errors.Error {

	cipher := crypto.NewCipher(client, j.KMSKeyID, j.EncryptionContext)

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return err
	}

	cred := &Credential{
		Name:        name,
		Description: description,
		AddedAt:     time.Now().UTC().Truncate(time.Second),
		RotatedAt:   nil,
		Ciphertext:  ciphertext,
	}

	j.Credentials = append(j.Credentials, cred)
	return nil

}

// ExportPlaintext deciphers all the credentials and publishes them to a channel
// for formatting.
func (j *Store) ExportPlaintext(client kms.Client) (chan formatter.Item, errors.Error) {

	items := make(chan formatter.Item, len(j.Credentials))
	cipher := crypto.NewCipher(client, j.KMSKeyID, j.EncryptionContext)

	for _, item := range j.Credentials {

		plaintext, err := cipher.Decrypt(item.Ciphertext)
		if err != nil {
			close(items)
			return items, err
		}

		items <- formatter.Item{Name: item.Name, Plaintext: plaintext}

	}

	close(items)
	return items, nil

}

// Find returns the credential corresponding to a name
func (j *Store) Find(name string) *Credential {

	for _, item := range j.Credentials {

		if item.Name == name {
			return item
		}

	}

	return nil

}

// RotateMasterKey re-encrypts all the credentials with the new given KMS key
func (j *Store) RotateMasterKey(client kms.Client, newKMSKeyID string) errors.Error {

	oldCipher := crypto.NewCipher(client, j.KMSKeyID, j.EncryptionContext)
	newCipher := crypto.NewCipher(client, newKMSKeyID, j.EncryptionContext)

	for _, item := range j.Credentials {

		oldPlaintext, err := oldCipher.Decrypt(item.Ciphertext)
		if err != nil {
			return errors.WrapPrefix(err, fmt.Sprintf("Unable to decrypt credential: %s", item.Name), 0)
		}

		newCiphertext, err := newCipher.Encrypt(oldPlaintext)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to encrypt credential", 0)
		}

		item.Ciphertext = newCiphertext

	}

	j.KMSKeyID = newKMSKeyID
	return nil

}

// Rotate changes the plaintext of a stored credential. A new data key is generated.
func (j *Store) Rotate(client kms.Client, name string, newPlaintext string) errors.Error {

	item := j.Find(name)
	if item == nil {
		return errors.Errorf("Unable to find %s", name)
	}

	cipher := crypto.NewCipher(client, j.KMSKeyID, j.EncryptionContext)

	oldPlaintext, err := cipher.Decrypt(item.Ciphertext)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to decrypt credential", 0)
	}

	if oldPlaintext == newPlaintext {
		return errors.Errorf("Trying to rotate a credential and giving the same value")
	}

	newCiphertext, err := cipher.Encrypt(newPlaintext)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to encrypt credential", 0)
	}

	now := time.Now().UTC().Truncate(time.Second)
	item.Ciphertext = newCiphertext
	item.RotatedAt = &now

	return nil

}
