## ejson-kms add

add a secret

### Synopsis


add: Add a secret to a secrets file.

The name of the secret must be in lowercase and can only contain letters,
digits and underscores. It cannot start with a digit. This is to ensure
compatibility with the shell when using the export command.

An optional, freeform, description can be provided. Use it to describe what the
item is for, how to rotate it, who is responsible and when...

It will ask you to type the secret at runtime, to avoid saving it to your
shell history. If you need to pass in the contents of a file (such as TLS keys),
you can pipe it's contents to stdin.
Please be mindful of your bash history when piping in strings.

```
ejson-kms add NAME
```

### Examples

```
ejson-kms add password
ejson-kms add password --path="secrets.json"
ejson-kms add password --description="Nuclear launch code"
cat tls-cert.key | ejson-kms add tls_key
```

### Options

```
      --description string   freeform description of the secret
      --path string          path of the secrets file (default ".secrets.json")
```

### SEE ALSO
* [ejson-kms](ejson-kms.md)	 - ejson-kms manages your secrets using Amazon KMS and a simple JSON file

