package model

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/adrienkohlbecker/errors"
)

// JSON represents a credentials file.
type JSON struct {
	// KMSKeyARN is an aws ARN pointing to the master key used to encrypt the
	// credentials in this file.
	//
	// This value can be a globally
	// unique identifier, a fully specified ARN to either an alias or a key, or
	// an alias name prefixed by "alias/".
	//
	//   Key ARN Example - arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
	//
	//   Alias ARN Example - arn:aws:kms:us-east-1:123456789012:alias/MyAliasName
	//
	//   Globally Unique Key ID Example - 12345678-1234-1234-1234-123456789012
	//
	//   Alias Name Example - alias/MyAliasName
	KMSKeyArn string `json:"kms_key_arn"`

	// Name/value pair that contains additional data to be authenticated during
	// the encryption and decryption processes that use the key. This value is logged
	// by AWS CloudTrail to provide context around the data encrypted by the key.
	//
	// Note that changing this value requires re-encrypting every credential
	// in the file, since KMS uses it as part of the decryption process.
	Context map[string]*string `json:"context"`

	// Credentials is a list of credentials
	Credentials []Credential `json:"credentials"`
}

// Credential represents a given credential
type Credential struct {
	// Name is the name of the credential used during exporting.
	// As such, by convention and for ease of use in bash scripts (for example),
	// it must be comprised of lowercase characters, digits and underscores only.
	// Moreover, it cannot start with a number.
	Name string `json:"name"`

	// Description is a free-form explanation of what the credential is used for.
	// Common use cases include : how to rotate the credential, how it is used
	// in the code, ...
	Description string `json:"desctiption"`

	// AddedAt is set when running `ejson-kms add`, and is purely informational.
	AddedAt time.Time `json:"added_at"`

	// RotatedAt is set when running `ejson-kms rotate`,
	// and is purely informational.
	RotatedAt *time.Time `json:"rotated_at"`

	// Ciphertext contains the encrypted credential value, the plaintext nonce,
	// along with the encrypted data key used for this specific credential.
	// A versioning field is also added, currently only `EJK1]`
	Ciphertext string `json:"ciphertext"`
}

// Import takes a path to a credentials file and returns the contents of the
// file unmarshaled in the model.
func Import(path string) (*JSON, errors.Error) {

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to read file at %s", path), 0)
	}

	j := &JSON{}
	err = json.Unmarshal(bytes, j)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to decode JSON at %s", path), 0)
	}

	return j, nil

}

// NameExists is a convenience wrapper to check for the existence of a given
// credential in the file.
func (j *JSON) NameExists(name string) bool {

	for _, item := range j.Credentials {
		if item.Name == name {
			return true
		}
	}

	return false

}

// Export takes a JSON struct and writes it to disk to the given path.
// The JSON is pretty-printed and file permissions are set to 0644.
func (j *JSON) Export(path string) errors.Error {

	bytes, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		// Note: not covered by tests as no error can be hit with the current schema
		return errors.WrapPrefix(err, "Unable to marshall JSON", 0)
	}

	bytes = append(bytes, []byte("\n")...)

	err = ioutil.WriteFile(path, bytes, 0644)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to write file at path %s", path), 0)
	}

	return nil

}
