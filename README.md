# ejson-kms

[![GoDoc](https://godoc.org/github.com/adrienkohlbecker/ejson-kms?status.svg)](https://godoc.org/github.com/adrienkohlbecker/ejson-kms) [![CircleCI](https://circleci.com/gh/adrienkohlbecker/ejson-kms/tree/master.svg?style=shield)](https://circleci.com/gh/adrienkohlbecker/ejson-kms/tree/master) [![Coverage Status](https://coveralls.io/repos/github/adrienkohlbecker/ejson-kms/badge.svg?branch=master)](https://coveralls.io/github/adrienkohlbecker/ejson-kms?branch=master)

`ejson-kms` is a utility for managing a collection of secrets in source control using AWS KMS.

The secrets are encrypted using secret-key cryptography (NaCl Secretbox: [XSalsa20][XSalsa20] + [Poly1305][Poly1305]), using key wrapping with a master key stored on HSM-backed storage at AWS. Encrypted secrets are stored in a JSON file that can easily be shared and versioned.


# Quick start

1. Install ejson-kms (see [Installation](#installation))
2. Create a KMS master key on AWS
3. Create a secrets file with `ejson-kms init --kms-key-id="alias/MyKMSKey"`
4. Add an encrypted secret with `ejson-kms add secret`
5. Use the decrypted credential in your bash scripts with `eval "$(ejson-kms export)"`

# What is it

Software systems often need access to some shared credential. For example, your web application needs access to a database password, or an API key for some third party service.

`ejson-kms` is a simple tool that provides secure credential storage using a JSON file stored and versioned with your project, while delegating the security of your credentials to AWS KMS.

The main benefits provided by `ejson-kms` are:

* Secrets can be safely stored in a git repository.
* Changes to secrets are auditable on a line-by-line basis with git blame.
* Any number of access control policies can be implemented using IAM roles
* Usage audit is possible using encryption contexts and CloudTrail
* Secrets change synchronously with application source (as opposed to secrets provisioned by Configuration Management).
* Simple, well-tested, easily-auditable source.

# How it works

## File format

Secrets are stored in a JSON file with the following schema:

```json
{
  "kms_key_id": "arn:aws:kms:eu-west-1:000123456789:alias/ejson-kms",
  "version": 1,
  "encryption_context": {
    "KEY": "VALUE"
  },
  "secrets": [
    {
      "name": "secret",
      "description": "Nuclear launch codes",
      "ciphertext": "EJK1;AQEDAHhZurRVk3ZWIqpympXccBmx1cOFJmQj8RBnIk01CJMnTAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDCgMdhWkV5uphiD5DQIBEIA7kkXS7izLJ9X4x5spWTqWjLmSY/dtcQBeaXSlzcQA5Hqd+dvdMShqcEvd3RfUzZGR89qZYzrTsfybRA4=;4vukkc/Z8K9rSkex+s7XpphIIldqNcPJjhvhOixiq6RM7pMfijLMsvTNEyQKLw=="
    }
  ]
}
```

## Encryption context

AWS gives us the ability to store an arbitrary context with each secret, in the form of key-value pairs.

These key-value pairs are stored with the secret and are logged in CloudTrail for each encryption/decryption operation. You can use it for auditing purposes by adding, for example, the name of the project or the type of environment (production, staging, ...). Additionally, you can use it to further restrict access to your credentials with IAM policies.

Note: Since the context is stored with the secret and authenticated, it is **read-only**: once a secret has been encrypted, you cannot change the context.

## Secret encryption

* For each secret, a data key is requested from AWS KMS (see [GenerateDataKey][GenerateDataKey]).
* The encryption context is sent along and is stored alongside
the encrypted data key. The name of the secret is added to the context
automatically under the key `Secret`
* KMS returns the data key encrypted with the master key (stored on AWS servers) and the corresponding plaintext.
* That data key is used to encrypt one secret.
* A random nonce is generated and NaCL Secretbox is used for encryption.
* Under the hood, Secretbox uses [XSalsa20][XSalsa20] and [Poly1305][Poly1305] to encrypt and
authenticate messages. The length of messages is not hidden.
* Finally, the encrypted data key, the random nonce and the encrypted secret are each stored in the JSON file.

## Secrets decryption

* For each secret, the encrypted data key, random nonce and encrypted secret
are extracted from the JSON file.
* A request is made to AWS KMS to decrypt the encrypted data key (see [Decrypt][Decrypt]).
* At this stage the encryption context is authenticated and logged. The name of the secret is added to the context automatically under the key `Secret`
* Using the key plaintext and random nonce, the secret is decrypted using
NaCL Secretbox.

# Comparison with other tools

## ejson

[ejson][ejson] is the main inspiration for this project. `ejson-kms` is thus very similar but differs in a few ways:

* While `ejson` uses public-key cryptography with keys stored on the filesystem, `ejson-kms` uses secret-key cryptography, key wrapping and a master key stored on HSM-backed storage in AWS servers.
* `ejson` has a free-form file format, any kind of schema can be implemented since it will encrypt all json keys that do not start with a `_`. `ejson-kms` has a fixed schema.
* `ejson` encourages secrets to be written in plaintext on the filesystem during encryption (You first add the plaintext to the file, then encrypt it). `ejson-kms` never writes your secrets in plaintext anywhere.

You can learn more about `ejson` in the write-up published on Shopify's blog here: https://engineering.shopify.com/79963908-secrets-at-shopify-introducing-ejson

## credstash

[credstash][credstash] is the source of inspiration for `ejson-kms`'s encryption workflow. It differs in a few ways:

* `credstash` depends on DynamoDB for credential storage, `ejson-kms` uses the filesystem. Consequently, auditing and versioning protocols are very different.
* `credstash` is a python tool and has a few dependencies. `ejson-kms` is distributed as a single, statically-linked binary.

You can learn more about credstash and KMS encryption here: https://blog.fugue.co/2015-04-21-aws-kms-secrets.html

## Ansible Vault

[Ansible Vault][Ansible Vault] is a feature of Ansible designed to store secrets alongside playbooks. However, it uses whole-file encryption, meaning changes are not easily auditable and using `git blame` is impossible.

## Hashicorp Vault

[Hashicorp Vault][Hashicorp Vault] is a tool designed to store secrets but also a number of features that are out of scope of `ejson-kms` such as certificate generation or AWS credentials management.

It is a complicated daemon you have to keep running in your infrastructure, as opposed to `ejson-kms` which you only have to install and use on the CLI.

# Dependencies

`ejson-kms` as a binary has no dependencies.

It depends, however, on AWS KMS for cryptography.

# Installation

Binaries for Linux, OSX and Windows are provided in the GitHub Releases page.

The binaries are signed using the GPG key `C248DE6357445D6302F9A62E74BFD03C20CC21AF`.

## Linux

You can install `ejson-kms` on Linux with the following:

```bash
export EJSON_KMS_VERSION="3.0.0"
curl -Lo ejson-kms https://github.com/adrienkohlbecker/ejson-kms/releases/download/$EJSON_KMS_VERSION/ejson-kms-$EJSON_KMS_VERSION-linux-amd64
curl -Lo ejson-kms.asc https://github.com/adrienkohlbecker/ejson-kms/releases/download/$EJSON_KMS_VERSION/ejson-kms-$EJSON_KMS_VERSION-linux-amd64.asc
gpg --keyserver ha.pool.sks-keyservers.net --recv-keys C248DE6357445D6302F9A62E74BFD03C20CC21AF
gpg --verify ejson-kms.asc
chmod +x ejson-kms
```

## OSX

You can install `ejson-kms` using [Homebrew](http://brew.sh):

```bash
brew install adrienkohlbecker/ejson-kms/ejson-kms
```

## From source

`ejson-kms` requires a working Go 1.6+ installation.

You can install ejson-kms from source with:

```bash
go get -u github.com/adrienkohlbecker/ejson-kms
```

# Usage

Detailed usage instructions are available in the [doc](./doc/md/ejson-kms.md) folder.

## init

Create an empty secrets file with `ejson-kms init --kms-key-id="alias/MyKMSKey"`.

* Change the path of the file (by default `./.secrets.json`) with `--path=my_secrets.json`
* Provide an encryption context with `--encryption-context="key1=value1,key2=value2"`

Note: the encryption context is **read-only**. If you want to change it you will have to start over with an empty file. A facility to edit the context might be added to `ejson-kms` in the future (contributions welcome!)

## add

Add a secret with `ejson-kms add SECRET_NAME`

* `ejson-kms` will ask you to type the secret at runtime.
* Alternatively, you can use the form `echo "password" | ejson-kms add secret`, but be mindful of your bash history if you do so.
* To store the contents of a file (such as a TLS key), use `cat tls.key | ejson-kms add tls_key`
* Optionally, you can provide a description for this secret using `--description="Nuclear launch codes"`. Use it to describe what the secret is used for, how to rotate it...
* The name of the credential can include lower-case letters, digits, and underscores. They cannot start with numbers (for compatibility with bash on export). Valid names: `password`, `api_key`, `secret_123`. Invalid names: `Password`, `API KEY`, `123-secret`.

## rotate

Rotate the value of a secret with `ejson-kms rotate SECRET_NAME`

* Secret entry is identical to the `add` command
* The secret will first be decrypted to check if the values are indeed different

## rotate-kms-key

To rotate the KMS master key used in a secrets file, use `ejson-kms rotate-kms-key NEW_KMS_KEY_ID`.

Every secret will be decrypted with the old key, encrypted with the new key and the file will be overwritten.

## export

To use your decrypted secrets, you can export them in a few formats with `ejson-kms export --format=bash`. The export will be output to standard out.

Currently there are 3 formats supported:
* `bash`: `SECRET='password'` (name is capitalized, value as-is except escaping of `'` with `''`)
* `dotenv`: `SECRET="password"` (name is capitalized, value uses escape sequences (\t, \n, \xFF, \u0100) for non-ASCII characters and non-printable characters)
* `json`: `{ "secret": "password" }`

To use in a bash script, do the following:

```bash
#!/bin/bash

eval "$(ejson-kms export)"

echo "$SECRET"
```

# AWS authentication

`ejson-kms` will look for AWS credentials in the following locations and order:

* **Environment variables**:
  * Access Key ID: `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`
  * Secret Access Key: `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`
  * Region: `AWS_REGION`
  * If using an IAM role: `AWS_SESSION_TOKEN`
* **Shared credentials file**:
  * If `AWS_SHARED_CREDENTIALS_FILE` is set, this path will be used
  * Otherwise `$HOME/.aws/credentials` on Linux/OSX and `%USERPROFILE%\.aws\credentials` on Windows
  * An AWS profile can be set with the `AWS_PROFILE` environment variable, otherwise it will use the default profile.
  * If you need to load the AWS region from ~/.aws/config, you need to set `AWS_SDK_LOAD_CONFIG=true`, otherwise you need to set `AWS_REGION`
* **Instance profile**: On EC2 instances with an assigned instance role

See also [the AWS SDK session documentation](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/).

# IAM policies

Below are the basic IAM policies needed to give access to `ejson-kms` to a user. More complex policies can be devised, especially using encryption contexts. Refer to the documentation of AWS KMS and IAM for more information.

## Secret writer

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:GenerateDataKey"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
    }
  ]
}
```

## Secret reader

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
    }
  ]
}
```

## Secret reader scoped by Encryption Context

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "kms:Decrypt"
    ],
    "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID",
    "Condition": {
      "StringEquals": {
        "kms:EncryptionContext:MY_KEY": "MY_VALUE"
      }
    }
  }
}
```

# Versioning

`ejson-kms` follows [Semantic Versioning](http://semver.org/). For the versions available, see the [releases on this repository](https://github.com/adrienkohlbecker/ejson-kms/releases).

# Authors

[Adrien Kohlbecker](https://github.com/adrienkohlbecker)

See also the list of [contributors](https://github.com/adrienkohlbecker/ejson-kms/contributors) who participated in this project.

# License

`ejson-kms` is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

# Acknowledgments

This project was heavily inspired by [ejson][ejson] and [credstash][credstash].


[XSalsa20]: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
[Poly1305]: http://cr.yp.to/mac.html
[GenerateDataKey]: http://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
[Decrypt]: http://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
[ejson]: https://github.com/Shopify/ejson
[credstash]: https://github.com/fugue/credstash
[Ansible Vault]: http://docs.ansible.com/ansible/playbooks_vault.html
[Hashicorp Vault]: https://www.vaultproject.io/
