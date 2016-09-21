## ejson-kms rotate

rotate a secret

### Synopsis


rotate: Rotate a secret from a secrets file.

This will decrypt the given secret, check that the values are indeed different,
and store the new encrypted value.

It will ask you to type the secret at runtime, to avoid saving it to your
shell history. If you need to pass in the contents of a file (such as TLS keys),
you can pipe it's contents to stdin.
Please be mindful of your bash history when piping in strings.

```
ejson-kms rotate NAME
```

### Examples

```
ejson-kms rotate password
cat tls-cert.key | ejson-kms rotate tls_key
```

### Options

```
      --path string   path of the secrets file (default ".secrets.json")
```

### SEE ALSO
* [ejson-kms](ejson-kms.md)	 - ejson-kms manages your secrets using Amazon KMS and a simple JSON file

