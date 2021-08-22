# 4.3.0 - August 22nd, 2021

* Added `bash-ifnotset` and `bash-ifempty` formatters

# 4.2.0 - August 22nd, 2021

* Switched to go modules and go 1.16
* Added darwin/linux arm64 binary

# 4.1.0 - March 27th, 2019

* Added support for yaml files in export subcommand.

# 4.0.0 - January 29th, 2019

* Vendoring go dependencies using dep rather than gvt
* Use go-errors/errors upstream rather than own fork. This is breaking change for projects using this as a library as it changes the return type of most methods from `errors.Error` to `error`.

# 3.0.0 - October 11th, 2016

* Removed the `export` keyword from BASH formatter.
* This is a breaking change that provides more secure defaults. Specifically,
you will need to export the environment variables yourself if your app needs
them outside of the BASH script.

# 2.0.0 - October 10th, 2016

* Changed BASH escaping in export, now uses single quotes and no string processing.
* This is a breaking change, but is necessary to preserve multi-line strings such
as TLS keys when using the `eval "$(ejson-kms export)"` idiom.

# 1.0.1 - October 6th, 2016

* Fixed `echo "foo\nbar" | ejson-kms add` previously added only the first line

# 1.0.0 - September 28th, 2016

* Initial release of `ejson-kms`
