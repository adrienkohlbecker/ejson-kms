// Package kms implements a client to AWS KMS.
//
// Example:
//
//   client := kms.DefaultClient() // uses default AWS credentials locations
//   kms.GenerateDataKey(client, kmsKeyID, encryptionContext)
//   => kms.DataKey{Ciphertext: "abcd...", Plaintext: "foo..."}
//   kms.DecryptDataKey(client, key.Ciphertext, encryptionContext)
//   => kms.DataKey{Ciphertext: "abcd...", Plaintext: "foo..."}
package kms
