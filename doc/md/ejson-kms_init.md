## ejson-kms init

create a new secrets file

### Synopsis


init: Create a new secrets file.

You must provide an AWS KMS key ID, which can take multiple forms (see examples).

Optionaly, you can add en encryption context to the generated file, in the form
of key-value pairs. Note that the only way to modify this context afterwards is
via the "edit-context" command.
Manually editing it in the JSON file will render the file un-decipherable.

If a file exists at the destination, the command will exit. You can change the
default destination path (.secrets.json) with the "--path" flag.

```
ejson-kms init --kms-key-id=KMS_KEY_ID
```

### Examples

```
ejson-kms init --kms-key-id="arn:aws:kms:us-east-1:123456789012:alias/MyAliasName"
ejson-kms init --kms-key-id="alias/MyAliasName" --encryption-context="KEY1=VALUE1,KEY2=VALUE2"
ejson-kms init --kms-key-id="12345678-1234-1234-1234-123456789012" --path="secrets.json"
```

### Options

```
      --encryption-context stringSlice   encryption context added to the data keys ("KEY1=VALUE1,KEY2=VALUE2")
      --kms-key-id string                KMS Key ID of your master encryption key for this file
      --path string                      path of the generated file (default ".secrets.json")
```

### SEE ALSO
* [ejson-kms](ejson-kms.md)	 - ejson-kms manages your secrets using Amazon KMS and a simple JSON file

