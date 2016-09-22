// Package crypto implements cryptography for secrets.
//
// Under the hood, it leverages AWS KMS for master key management and key wrapping,
// and nacl/secretbox for encryption and authentication.
//
// Secrets are encrypted as follows:
//
// * For each `Encrypt` operation, a new 256 bits data key is requested from KMS.
//   which returns both the key in plaintext and in encrypted form.
// * This key is then fed to nacl/secretbox, along with a 192 bits random nonce,
//   generated from go's default CSPRNG (see the crypto/rand package). secretbox
//   uses XSalsa20 and Poly1305 to encrypt and authenticate messages.
// * The secret ciphertext consists of the random nonce and the encrypted secret.
// * The encrypted data key and the encrypted secret are then base64-encoded
//   and returned as a string, along with a versioning field.
//
// Secrets are decrypted as follows:
//
// * The encrypted data key and encrypted secret are extracted from the input
// * A request is made to AWS KMS to decypt the data key. AWS returns the data
//   key plaintext.
// * The nonce and secret ciphertext are extracted from the secret ciphertext,
//   and fed to nacl/secretbox for authentication and decryption.
//
// The format of the encrypted strings is:
//
//   "EJK1];abcdef...;foobar..."
//    ^-- versionning field allowing algorithm changes in the future
//          ^-- base64 encoded encrypted data key
//                    ^-- base64 encoded [random nonce, encrypted secret]
package crypto
