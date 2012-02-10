// Copyright 2012 The Obvious Corporation.

/*
 * "ursa": RSA crypto, with an emphasis on Buffer objects
 */

/*
 * Modules used
 */

// Note: This also forces OpenSSL to be initialized, which is important!
var crypto = require("crypto");

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

/** hash algorithm constant */
var MD5    = "md5";


/*
 * Helper functions
 */

/**
 * Return a buffer containing the encoding of the given bigint for use
 * as part of an SSH-style public key file. The input value must be a
 * buffer representing an unsigned bigint in big-endian order.
 */
function toSshBigint(value) {
    // The output is signed, so we need to add an extra 00 byte at the
    // head if the high-order bit is set.
    var prefix00 = ((value[0] & 0x80) !== 0);
    var length = value.length + (prefix00 ? 1 : 0);
    var result = new Buffer(length + 4);
    var offset = 0;
	
    result.writeUInt32BE(length, offset);
    offset += 4;

    if (prefix00) {
	result[offset] = 0;
	offset++;
    }

    value.copy(result, offset);
    return result;
}

/**
 * Create and return a buffer containing an ssh-style public key file for
 * the given RsaWrap object.
 *
 * For the record, an ssh-style public key file consists of three
 * concatenated values, each one length-prefixed:
 *
 *     literal string "ssh-rsa"
 *     exponent
 *     modulus
 *
 * The literal string header is length-prefixed.  The two numbers are
 * represented as signed big-int values in big-endian order, also
 * length-prefixed.
 */
function createSshPublicKey(rsa) {
    var e = toSshBigint(rsa.getExponent());
    var m = toSshBigint(rsa.getModulus());

    var header = toSshBigint(new Buffer("ssh-rsa", UTF8));
    var result = new Buffer(header.length + m.length + e.length);
    var offset = 0;

    header.copy(result, offset);
    offset += header.length;
    e.copy(result, offset);
    offset += e.length;
    m.copy(result, offset);

    return result;
}

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
 * Return a buffer or undefined argument as-is, or convert a given
 * string into a buffer by using the indicated encoding. An undefined
 * encoding is interpreted to mean UTF8.
 */
function decodeString(str, encoding) {
    if ((str === undefined) || Buffer.isBuffer(str)) {
        return str;
    }

    if (encoding === undefined) {
        encoding = UTF8;
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

    function toPublicSsh(encoding) {
        return encodeBuffer(createSshPublicKey(rsa), encoding);
    }

    function toPublicSshFingerprint(encoding) {
        return sshFingerprint(createSshPublicKey(rsa), encoding);
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
 */
function createPublicKey(pem, encoding) {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(decodeString(pem, encoding));

    return PublicKey(rsa);
}

/**
 * Create a new private key object, from the given PEM-encoded file,
 * optionally decrypting the file with a password. The arguments may
 * be either Buffers (whose contents are interpreted as ASCII / UTF8)
 * or strings. The password may be left undefined, in which case the
 * file is assumed not to be encrypted.
 */
function createPrivateKey(pem, password, encoding) {
    var rsa = new RsaWrap();
    pem = decodeString(pem, encoding);
    password = decodeString(password, encoding);

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

/**
 * Return the SSH-style public key fingerprint of the given SSH-format
 * public key.
 */
function sshFingerprint(sshKey, sshEncoding, outEncoding) {
    var hash = crypto.createHash(MD5);

    hash.update(decodeString(sshKey, sshEncoding));
    var result = new Buffer(hash.digest(BINARY), BINARY);
    return encodeBuffer(result, outEncoding);
}


/*
 * Initialization
 */

module.exports = {
    createPrivateKey:   createPrivateKey,
    createPublicKey:    createPublicKey,
    generatePrivateKey: generatePrivateKey,
    sshFingerprint:     sshFingerprint
};
