package model

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/adrienkohlbecker/ejson-kms/crypto"
	"github.com/adrienkohlbecker/ejson-kms/formatter"
	"github.com/adrienkohlbecker/ejson-kms/kms"
	"github.com/go-errors/errors"
)

// Store represents a secrets file.
type Store struct {
	// _hidden is a dummy hidden key to force the use of explicit keys when
	// initializing the struct. Allows adding keys in the future without
	// breaking code
	_hidden struct{}

	// Name/value pair that contains additional data to be authenticated during
	// the encryption and decryption processes that use the key. This value is logged
	// by AWS CloudTrail to provide context around the data encrypted by the key.
	//
	// Note that changing this value requires re-encrypting every secret
	// in the file, since KMS uses it as part of the decryption process.
	EncryptionContext map[string]*string `json:"encryption_context"`

	// KMSKeyID is an aws ID pointing to the master key used to encrypt the
	// secrets in this file.
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

	// Secrets is a list of secrets
	Secrets []*Secret `json:"secrets"`

	// Version is the version of the JSON schema to use. For now there is only
	// version 1.
	Version int `json:"version"`
}

// NewStore returns a new empty store
func NewStore(kmsKeyID string, encryptionContext map[string]*string) *Store {

	return &Store{
		KMSKeyID:          kmsKeyID,
		Version:           1,
		EncryptionContext: encryptionContext,
		Secrets:           make([]*Secret, 0),
	}

}

// Load takes a path to a secrets file and returns the contents of the
// file unmarshaled in the model.
func Load(path string) (*Store, error) {

	bytes, err := ioutil.ReadFile(path) // nolint: gosec
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to read file at %s", path), 0)
	}

	store := &Store{}
	err = json.Unmarshal(bytes, store)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to decode Store at %s", path), 0)
	}

	return store, nil

}

// Contains is a convenience wrapper to check for the existence of a given
// secret in the file.
func (s *Store) Contains(name string) bool {
	return s.Find(name) != nil
}

// Save takes a Store struct and writes it to disk to the given path.
// The JSON is pretty-printed and file permissions are set to 0644.
func (s *Store) Save(path string) error {

	bytes, err := json.MarshalIndent(s, "", "  ")
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

// Add adds a new secret to the store
//
// Note that the name of the secret is automatically added to the encryption
// context under the key "Secret"
func (s *Store) Add(client kms.Client, plaintext string, name string, description string) error {

	context := make(map[string]*string)
	for k, v := range s.EncryptionContext {
		context[k] = v
	}
	context["Secret"] = &name

	cipher := crypto.NewCipher(client, s.KMSKeyID)

	ciphertext, err := cipher.Encrypt(plaintext, context)
	if err != nil {
		return err
	}

	cred := &Secret{
		Name:        name,
		Description: description,
		Ciphertext:  ciphertext,
	}

	s.Secrets = append(s.Secrets, cred)
	return nil

}

// ExportPlaintext deciphers all the secrets and publishes them to a channel
// for formatting.
func (s *Store) ExportPlaintext(client kms.Client) (chan formatter.Item, error) {

	items := make(chan formatter.Item, len(s.Secrets))
	cipher := crypto.NewCipher(client, s.KMSKeyID)

	for _, item := range s.Secrets {

		context := make(map[string]*string)
		for k, v := range s.EncryptionContext {
			context[k] = v
		}
		context["Secret"] = &item.Name

		plaintext, err := cipher.Decrypt(item.Ciphertext, context)
		if err != nil {
			close(items)
			return items, err
		}

		items <- formatter.Item{Name: item.Name, Plaintext: plaintext}

	}

	close(items)
	return items, nil

}

// Find returns the secret corresponding to a name
func (s *Store) Find(name string) *Secret {

	for _, item := range s.Secrets {

		if item.Name == name {
			return item
		}

	}

	return nil

}

// RotateKMSKey re-encrypts all the secrets with the new given KMS key
func (s *Store) RotateKMSKey(client kms.Client, newKMSKeyID string) error {

	oldCipher := crypto.NewCipher(client, s.KMSKeyID)
	newCipher := crypto.NewCipher(client, newKMSKeyID)

	for _, item := range s.Secrets {

		context := make(map[string]*string)
		for k, v := range s.EncryptionContext {
			context[k] = v
		}
		context["Secret"] = &item.Name

		oldPlaintext, err := oldCipher.Decrypt(item.Ciphertext, context)
		if err != nil {
			return errors.WrapPrefix(err, fmt.Sprintf("Unable to decrypt secret: %s", item.Name), 0)
		}

		newCiphertext, err := newCipher.Encrypt(oldPlaintext, context)
		if err != nil {
			return errors.WrapPrefix(err, "Unable to encrypt secret", 0)
		}

		item.Ciphertext = newCiphertext

	}

	s.KMSKeyID = newKMSKeyID
	return nil

}

// Rotate changes the plaintext of a stored secret. A new data key is generated.
//
// Note that the name of the secret is automatically added to the encryption
// context under the key "Secret"
func (s *Store) Rotate(client kms.Client, name string, newPlaintext string) error {

	item := s.Find(name)
	if item == nil {
		return errors.Errorf("Unable to find %s", name)
	}

	context := make(map[string]*string)
	for k, v := range s.EncryptionContext {
		context[k] = v
	}
	context["Secret"] = &item.Name

	cipher := crypto.NewCipher(client, s.KMSKeyID)

	oldPlaintext, err := cipher.Decrypt(item.Ciphertext, context)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to decrypt secret", 0)
	}

	if oldPlaintext == newPlaintext {
		return errors.Errorf("Trying to rotate a secret and giving the same value")
	}

	newCiphertext, err := cipher.Encrypt(newPlaintext, context)
	if err != nil {
		return errors.WrapPrefix(err, "Unable to encrypt secret", 0)
	}

	item.Ciphertext = newCiphertext
	return nil

}
