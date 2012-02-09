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

See the doc comments and tests.

License
-------

Apache 2. See the top-leve file `LICENSE.txt`.
