// Package model is the primary interface around a secrets file.
//
// It implements the functions needed to create a secrets file, add secrets,
// rotate them, and export them.
//
// Example
//
// Here are a few ways to use this package:
//
//   store := model.NewStore(kmsKeyID, encryptionContext)
//   store.Add(kmsClient, "secret", "password", "Password for nuclear launch")
//   store.Save("mysecrets.json")
//
//   store := store.Load("mysecrets.json")
//   store.Contains("secret") // true
//   store.Rotate(kmsClient, "secret", "new_password")
//   store.Export(formatter.Bash) // "export SECRET='new_password'"
//   store.Save("mysecrets.json")
//
//   store := store.Load("mysecrets.json")
//   store.RotateKMSKey(kmsClient, newKMSKeyID)
//   store.Save("mysecrets_rotated.json")
//
// Secret encryption
//
// For each secret, a data key is requested from AWS KMS.
//
// The encryption context is sent along and is stored alongside
// the encrypted data key. The name of the secret is added to the context
// automatically under the key "Secret"
//
// KMS returns the data key encrypted with the master key (stored on AWS servers)
// and the corresponding plaintext
//
// That data key is used to encrypt one secret.
//
// A random nonce is generated and nacl/secretbox is used for encryption.
//
// Under the hood, secretbox uses XSalsa20 and Poly1305 to encrypt and
// authenticate messages. The length of messages is not hidden.
//
// Finally, the encrypted key, the random nonce and the encrypted secret are
// each stored in the model.
//
// Secrets decryption
//
// For each secret, the encrypted data key, random nonce and encrypted secret
// are extracted from the model
//
// A request is made to AWS KMS to decrypt the encrypted data key. At this stage
// the encryption context is authenticated and logged. The name of the secret
// is added to the context automatically under the key "Secret"
//
// Using the key plaintext and random nonce, the secret is decrypted using
// nacl/secretbox.
package model
