// Copyright 2012 The Obvious Corporation.

/*
 * "rsab": RSA crypto, with an emphasis on Buffer objects
 */

/*
 * Modules used
 */

var rsabNative = require("../bin/rsabNative");

/*
 * Variable definitions
 */

/** encoding constant */
var UTF8 = "utf8";


/*
 * Exported bindings
 */

/**
 * Create a new public key object, from the given PEM-encoded file. The
 * argument may be either a Buffer (whose contents are interpreted as
 * ASCII / UTF8) or a string.
 *
 * Using a Buffer is more efficient. (A string argument is internally
 * converted into a buffer.)
 */
function pemToPublicKey(pem) {
    if (typeof pem === "string") {
	pem = new Buffer(pem, UTF8);
    }

    var result = new rsabNative.RsaWrap();
    result.setPublicKeyPem(pem);

    return result;
}

/**
 * Create a new private key object, from the given PEM-encoded file,
 * optionally decrypting the file with a password. The arguments may
 * be either Buffers (whose contents are interpreted as ASCII / UTF8)
 * or strings. The password may be left undefined, in which case the
 * file is assumed not to be encrypted.
 *
 * Using Buffers is more efficient. (A string argument is internally
 * converted into a buffer.)
 */
function pemToPrivateKey(pem, password) {
    if (typeof pem === "string") {
	pem = new Buffer(pem, UTF8);
    }

    if (typeof password === "string") {
	password = new Buffer(password, UTF8);
    }

    var result = new rsabNative.RsaWrap();
    result.setPrivateKeyPem(pem, password);

    return result;
}

/*
 * Initialization
 */

// This forces OpenSSL to be initialized.
require("crypto");

module.exports = {
    pemToPrivateKey: pemToPrivateKey,
    pemToPublicKey: pemToPublicKey,
    n: rsabNative // FIXME: TEMP!!
};
