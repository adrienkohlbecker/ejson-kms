package model

import "time"

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
