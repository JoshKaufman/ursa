// Copyright 2012 The Obvious Corporation.

/*
 * "ursa": RSA crypto, with an emphasis on Buffer objects
 */

/*
 * Modules used
 */

var RsaWrap = require("../bin/ursaNative").RsaWrap;

/*
 * Variable definitions
 */

/** encoding constant */
var BASE64 = "base64";

/** encoding constant */
var BINARY = "binary";

/** encoding constant */
var HEX    = "hex";

/** encoding constant */
var UTF8   = "utf8";



/*
 * Helper functions
 */

/**
 * Validate the given encoding name. Throws an exception if invalid.
 */
function validateEncoding(encoding) {
    switch (encoding) {
        case BASE64:
        case BINARY:
        case HEX:
        case UTF8: {
            // These are all valid.
            break;
        }
        default: {
            throw new Error("Invalid encoding: " + encoding);
        }
    }
}

/**
 * Convert a buffer into an appropriately-encoded string, or return it
 * unmodified if the encoding is undefined.
 */
function encodeBuffer(buf, encoding) {
    if (encoding === undefined) {
        return buf;
    }

    validateEncoding(encoding);
    return buf.toString(encoding);
}

/**
 * Convert a string into a buffer by using the indicated encoding, or
 * return the argument unmodified if the encoding is undefined (in
 * which case the argument should be a buffer).
 */
function decodeString(str, encoding) {
    if (encoding === undefined) {
        return str;
    }

    validateEncoding(encoding);
    return new Buffer(str, encoding);
}

/**
 * Public Key object. This is the externally-visible object that one gets
 * when constructing an instance from a public key. The constructor takes
 * a native RsaWrap object.
 */
function PublicKey(rsa) {
    function getExponent(encoding) {
        return encodeBuffer(rsa.getExponent(), encoding);
    }

    function getModulus(encoding) {
        return encodeBuffer(rsa.getModulus(), encoding);
    }

    function toPublicPem(encoding) {
        return encodeBuffer(rsa.getPublicKeyPem(), encoding);
    }

    function encrypt(buf, bufEncoding, outEncoding) {
        buf = decodeString(buf, bufEncoding);
        return encodeBuffer(rsa.publicEncrypt(buf), outEncoding);
    }

    function publicDecrypt(buf, bufEncoding, outEncoding) {
        buf = decodeString(buf, bufEncoding);
        return encodeBuffer(rsa.publicDecrypt(buf), outEncoding);
    }

    return {
        getExponent: getExponent,
        getModulus: getModulus,
        toPublicPem: toPublicPem,
        encrypt: encrypt,
        publicDecrypt: publicDecrypt,
    }
}

/**
 * Private Key object. This is the externally-visible object that one
 * gets when constructing an instance from a private key (aka a
 * keypair). The constructor takes a native RsaWrap object.
 */
function PrivateKey(rsa) {
    function toPrivatePem(encoding) {
        return encodeBuffer(rsa.getPrivateKeyPem(), encoding);
    }

    function decrypt(buf, bufEncoding, outEncoding) {
        buf = decodeString(buf, bufEncoding);
        return encodeBuffer(rsa.privateDecrypt(buf), outEncoding);
    }

    function privateEncrypt(buf, bufEncoding, outEncoding) {
        buf = decodeString(buf, bufEncoding);
        return encodeBuffer(rsa.privateEncrypt(buf), outEncoding);
    }

    var result = PublicKey(rsa);
    result.toPrivatePem   = toPrivatePem;
    result.decrypt        = decrypt;
    result.privateEncrypt = privateEncrypt;
    return result;
}


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
function createPublicKey(pem) {
    if (typeof pem === "string") {
        pem = new Buffer(pem, UTF8);
    }

    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(pem);

    return PublicKey(rsa);
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
function createPrivateKey(pem, password) {
    if (typeof pem === "string") {
        pem = new Buffer(pem, UTF8);
    }

    if (typeof password === "string") {
        password = new Buffer(password, UTF8);
    }

    var rsa = new RsaWrap();

    // Note: The native code is sensitive to the actual number of
    // arguments. It's *not* okay to pass undefined as a password.
    if (password) {
        rsa.setPrivateKeyPem(pem, password);
    } else {
        rsa.setPrivateKeyPem(pem);
    }

    return PrivateKey(rsa);
}

/**
 * Generate a new private key object (aka a keypair). The first
 * argument indicates the number of bits in the modulus (1024 or more
 * is generally considered secure). The second argument indicates the
 * exponent value, which must be odd (65537 is the typical value; 3
 * and 17 are also common).  Both arguments are optional and default
 * to 2048 and 65537 (respectively).
 */
function generatePrivateKey(modulusBits, exponent) {
    if (modulusBits === undefined) {
        modulusBits = 2048;
    }

    if (exponent === undefined) {
        exponent = 65537;
    }

    var rsa = new RsaWrap();
    rsa.generatePrivateKey(modulusBits, exponent);

    return PrivateKey(rsa);
}

/*
 * Initialization
 */

// This forces OpenSSL to be initialized.
require("crypto");

module.exports = {
    createPrivateKey:   createPrivateKey,
    createPublicKey:    createPublicKey,
    generatePrivateKey: generatePrivateKey
};
