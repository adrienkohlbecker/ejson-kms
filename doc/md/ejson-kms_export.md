## ejson-kms export

export the decrypted secrets

### Synopsis


export: Export a secrets file in it's decrypted form.

Each secret in the file will be decrypted and output to standard out.
A number of formats are available:

  * bash:   export SECRET="password"
  * dotenv: SECRET="password"
  * json:   { "secret": "password" }

Please be careful when exporting your secrets, do not save them to disk!

```
ejson-kms export
```

### Examples

```
ejson-kms export
ejson-kms export --format=json
ejson-kms export --path=secrets.json --format=dotenv
```

### Options

```
      --format string   format of the generated output (bash|dotenv|json) (default "bash")
      --path string     path of the secrets file (default ".secrets.json")
```

### SEE ALSO
* [ejson-kms](ejson-kms.md)	 - ejson-kms manages your secrets using Amazon KMS and a simple JSON file

