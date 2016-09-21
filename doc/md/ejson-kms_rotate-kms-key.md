## ejson-kms rotate-kms-key

rotates the KMS key used to encrypt the secrets

### Synopsis


rotate-kms-key: Rotates the KMS key used to encrypt a secrets file.

This command will decrypt all your secrets, and re-encrypt them using the
provided new KMS key.
The original file will be overwritten.

```
ejson-kms rotate-kms-key NEW_KMS_KEY_ID
```

### Examples

```
ejson-kms rotate-kms-key arn:aws:kms:us-east-1:123456789012:alias/MyAliasName
```

### Options

```
      --path string   path of the secrets file (default ".secrets.json")
```

### SEE ALSO
* [ejson-kms](ejson-kms.md)	 - ejson-kms manages your secrets using Amazon KMS and a simple JSON file

