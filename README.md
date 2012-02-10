ursa
====

This Node module provides wrappers for the RSA public/private key
crypto functionality of OpenSSL.

This module was inspired by
[node-rsa](https://github.com/chrisa/node-rsa) by Chris Andrews.  To
be clear, there are a few lines that I (danfuzz) used from its
`wscript` build file, but other than that this code is new.

Installing
----------

```shell
npm install ursa
```

Or grab the source and

```shell
node-waf configure build
```

Testing
-------

```shell
node ./test/test.js
```

Usage
-----

This library aims to be convenient to use, allowing one to pass in and
get back regular string objects. However, it is also meant to be reasonably
easy to use efficiently, allowing one to pass in and get back Buffer
objects. Using Buffers is always the more efficient option.

The library knows how to read and output PEM format files for both
public and private keys, and it can generate new private keys (aka
keypairs).

The usual public-encryption / private-decryption operations are always
done using padding mode `RSA_PKCS1_OAEP_PADDING`, which is the recommended
mode for all new applications (as of this writing). Note that this mode
builds-in a random element into every encryption operation, making it
unnecessary to waste time or effort adding randomness in at a higher layer.

The less well-understood private-encryption / public-decryption operations
(used for building signature mechanisms) are always done using padding
mode `RSA_PKCS1_PADDING`. This doesn't build in any randomness (but that's
not usually a problem for applications that use these operations).

See the doc comments and tests for the excruciating details, but here's
a quick rundown of the available top-level exports and instance methods:

### `ursa.createPrivateKey(pem, password)`

Create and return a private key read in from the given PEM-format file.
If defined, the given password is used to decrypt the PEM file.

Both arguments may be either Buffer objects or strings. If they are
strings, then they are internally converted to Buffers using `utf8`
encoding.

### `ursa.createPublicKey(pem)`

Create and return a public key read in from the given PEM-format file.

The argument may be either a Buffer objects or a strings. If it is
a string, then it is internally converted to a Buffer using `utf8`
encoding.

### `ursa.generatePrivateKey(modulusBits, exponent)`

Create and return a freshly-generated private key.


License
-------

Apache 2. See the top-level file `LICENSE.txt`.
