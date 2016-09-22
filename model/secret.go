package model

// Secret represents a given secret
type Secret struct {
	// Name is the name of the secret used during exporting.
	// As such, by convention and for ease of use in bash scripts (for example),
	// it must be comprised of lowercase characters, digits and underscores only.
	// Moreover, it cannot start with a number.
	Name string `json:"name"`

	// Description is a free-form explanation of what the secret is used for.
	// Common use cases include : how to rotate the secret, how it is used
	// in the code, ...
	Description string `json:"description"`

	// Ciphertext contains the encrypted secret value, the plaintext nonce,
	// along with the encrypted data key used for this specific secret.
	// A versioning field is also added, currently only `EJK1]`
	Ciphertext string `json:"ciphertext"`

	// force use of named fields to be able to add fields in the future
	_hidden bool
}
