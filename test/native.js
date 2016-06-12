// Copyright 2012 The Obvious Corporation.

/*
 * Tests of the underlying RsaWrap class.
 */

/*
 * Modules used
 */

"use strict";

var assert = require("assert");

var fixture    = require("./fixture");
var RsaWrap    = fixture.RsaWrap;
var ursaNative = fixture.ursaNative;
var textToNid  = ursaNative.textToNid;

/**
 * Asserts that two strings are equal, ignoring Windows newline differences
 */
function assertStringEqual(actual, expected, message) {
    assert.equal(actual.replace(/\r\n/g, '\n'), expected.replace(/\r\n/g, '\n'), message);
}

/*
 * Test functions
 */

function test_new() {
    new RsaWrap();
}

function test_setPrivateKeyPem() {
    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PASS_PRIVATE_KEY, fixture.PASSWORD);
}

function test_fail_setPrivateKeyPem() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.setPrivateKeyPem();
    }
    assert.throws(f1, /Missing args\[0]\./);

    function f2() {
        rsa.setPrivateKeyPem("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.setPrivateKeyPem(new Buffer("x"));
    }
    assert.throws(f3, /no start line/);

    function f4() {
        rsa.setPrivateKeyPem(fixture.PASS_PRIVATE_KEY, undefined);
    }
    assert.throws(f4, /Expected a Buffer in args\[1]\./);

    function f5() {
        rsa.setPrivateKeyPem(fixture.PASS_PRIVATE_KEY, "x");
    }
    assert.throws(f5, /Expected a Buffer in args\[1]\./);

    function f6() {
        rsa.setPrivateKeyPem(fixture.PASS_PRIVATE_KEY,
                             new Buffer("INCORRECT PASS"));
    }
    assert.throws(f6, /bad decrypt/);

    // Check for "set once."
    function f7() {
        rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    }
    f7();
    assert.throws(f7, /Key already set\./);
}

function test_setPublicKeyPem() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
}

function test_fail_setPublicKeyPem() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.setPublicKeyPem();
    }
    assert.throws(f1, /Missing args\[0]\./);

    function f2() {
        rsa.setPublicKeyPem("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.setPublicKeyPem(new Buffer("x"));
    }
    assert.throws(f3, /no start line/);

    // Check for "set once."
    function f4() {
        rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    }
    f4();
    assert.throws(f4, /Key already set\./);
}

function test_getExponent() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var value = rsa.getExponent().toString(fixture.HEX);
    assert.equal(value, fixture.EXPONENT_HEX);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    value = rsa.getExponent().toString(fixture.HEX);
    assert.equal(value, fixture.EXPONENT_HEX);
}

function test_fail_getExponent() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.getExponent();
    }
    assert.throws(f1, /Key not yet set\./);
}

function test_getModulus() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var value = rsa.getModulus().toString(fixture.HEX);
    assert.equal(value, fixture.MODULUS_HEX);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    value = rsa.getModulus().toString(fixture.HEX);
    assert.equal(value, fixture.MODULUS_HEX);
}

function test_fail_getModulus() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.getModulus();
    }
    assert.throws(f1, /Key not yet set\./);
}

function test_getPrivateExponent() {
    var rsa = new RsaWrap();
    rsa.createPrivateKeyFromComponents(
        fixture.PRIVATE_KEY_COMPONENTS.modulus,
        fixture.PRIVATE_KEY_COMPONENTS.exponent,
        fixture.PRIVATE_KEY_COMPONENTS.p,
        fixture.PRIVATE_KEY_COMPONENTS.q,
        fixture.PRIVATE_KEY_COMPONENTS.dp,
        fixture.PRIVATE_KEY_COMPONENTS.dq,
        fixture.PRIVATE_KEY_COMPONENTS.inverseQ,
        fixture.PRIVATE_KEY_COMPONENTS.d);

    var value = rsa.getPrivateExponent();
    assert.equal(value.toString(fixture.HEX), fixture.PRIVATE_KEY_COMPONENTS.d.toString(fixture.HEX));
}

function test_getPrivateKeyPem() {
    var keyStr = fixture.PRIVATE_KEY.toString(fixture.UTF8);

    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var pem = rsa.getPrivateKeyPem().toString(fixture.UTF8);
    assertStringEqual(pem, keyStr);
}

function test_getPrivateKeyPemWithPassPhrase() {
    var keyStr = fixture.PASS_PRIVATE_KEY.toString(fixture.UTF8);

    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PASS_PRIVATE_KEY, fixture.PASSWORD);

    var pem = rsa.getPrivateKeyPem(fixture.PASSWORD, fixture.DES_EDE3_CBC).toString(fixture.UTF8);
    assertStringEqual(pem, keyStr);
}

function test_fail_getPrivateKeyPem() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.getPrivateKeyPem();
    }

    assert.throws(f1, /Key not yet set\./);
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Expected a private key\./);
}

function test_getPublicKeyPem() {
    var keyStr = fixture.PUBLIC_KEY.toString(fixture.UTF8);

    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var pem = rsa.getPublicKeyPem().toString(fixture.UTF8);
    assertStringEqual(pem, keyStr);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    pem = rsa.getPublicKeyPem().toString(fixture.UTF8);
    assertStringEqual(pem, keyStr);
}

function test_fail_getPublicKeyPem() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.getPublicKeyPem();
    }
    assert.throws(f1, /Key not yet set\./);
}

function test_privateDecrypt() {
    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var encoded = new Buffer(fixture.PRIVATE_CIPHERTEXT_HEX, fixture.HEX);
    var decoded = rsa.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    encoded = new Buffer(fixture.PRIVATE_OLD_PAD_CIPHER_HEX, fixture.HEX);
    decoded = rsa.privateDecrypt(encoded, ursaNative.RSA_PKCS1_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_fail_privateDecrypt() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.privateDecrypt();
    }

    assert.throws(f1, /Key not yet set\./);
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Expected a private key\./);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    function f2() {
        rsa.privateDecrypt("x", ursaNative.RSA_PKCS1_OAEP_PADDING);
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.privateDecrypt(new Buffer("x"), ursaNative.RSA_PKCS1_OAEP_PADDING);
    }
    assert.throws(f3, /decoding error/);

    function f4() {
        rsa.privateDecrypt(new Buffer("x"), "str");
    }
    assert.throws(f4, /Expected a 32-bit integer/);
}

function test_publicEncrypt() {
    // No other reasonable way to test this than to do a round trip.
    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var priv = new RsaWrap();
    priv.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var encoded = rsa.publicEncrypt(plainBuf, ursaNative.RSA_PKCS1_OAEP_PADDING);
    var decoded = priv.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    encoded = priv.publicEncrypt(plainBuf, ursaNative.RSA_PKCS1_OAEP_PADDING);
    decoded = priv.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    // Test with old-style padding.
    encoded = rsa.publicEncrypt(plainBuf, ursaNative.RSA_PKCS1_PADDING);
    decoded = priv.privateDecrypt(encoded, ursaNative.RSA_PKCS1_PADDING);
    decoded = decoded.toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_fail_publicEncrypt() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.publicEncrypt();
    }

    assert.throws(f1, /Key not yet set\./);

    rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);

    function f2() {
        rsa.publicEncrypt("x", ursaNative.RSA_PKCS1_OAEP_PADDING);
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.publicEncrypt(new Buffer(2048), ursaNative.RSA_PKCS1_OAEP_PADDING);
    }
    assert.throws(f3, /too large/);

    function f4() {
        rsa.publicEncrypt(new Buffer("x"), "str");
    }
    assert.throws(f4, /Expected a 32-bit integer/);
}

function test_privateEncrypt() {
    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var encoded = rsa.privateEncrypt(plainBuf, ursaNative.RSA_PKCS1_PADDING).toString(fixture.HEX);

    assert.equal(encoded, fixture.PUBLIC_CIPHERTEXT_HEX);
}

function test_fail_privateEncrypt() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.privateEncrypt();
    }

    assert.throws(f1, /Key not yet set\./);

    rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Expected a private key\./);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    function f2() {
        rsa.privateEncrypt("x", ursaNative.RSA_PKCS1_PADDING);
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.privateEncrypt(new Buffer(2048), ursaNative.RSA_PKCS1_PADDING);
    }
    assert.throws(f3, /too large/);
}

function test_publicDecrypt() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var encoded = new Buffer(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX);
    var decoded = rsa.publicDecrypt(encoded, ursaNative.RSA_PKCS1_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    encoded = new Buffer(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX);
    decoded = rsa.publicDecrypt(encoded, ursaNative.RSA_PKCS1_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_fail_publicDecrypt() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.publicDecrypt();
    }

    assert.throws(f1, /Key not yet set\./);
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);

    function f2() {
        rsa.publicDecrypt("x", ursaNative.RSA_PKCS1_PADDING);
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.publicDecrypt(new Buffer("x"), ursaNative.RSA_PKCS1_PADDING);
    }
    assert.throws(f3, /padding_check/);
}

function test_generatePrivateKey() {
    var rsa = new RsaWrap();
    rsa.generatePrivateKey(512, 65537);

    // Do a round trip check.
    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var encoded = rsa.publicEncrypt(plainBuf, ursaNative.RSA_PKCS1_OAEP_PADDING);
    var decoded = rsa.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    // Extract the public key, and try using it for a round trip.
    var pubKey = new RsaWrap();
    pubKey.setPublicKeyPem(rsa.getPublicKeyPem());
    encoded = pubKey.publicEncrypt(plainBuf, ursaNative.RSA_PKCS1_OAEP_PADDING);
    decoded = rsa.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    // Similarly, try decoding with an extracted private key.
    var privKey = new RsaWrap();
    privKey.setPrivateKeyPem(rsa.getPrivateKeyPem());
    decoded = privKey.privateDecrypt(encoded, ursaNative.RSA_PKCS1_OAEP_PADDING).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_fail_generatePrivateKey() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.generatePrivateKey();
    }
    assert.throws(f1, /Missing args\[0]\./);

    function f2() {
        rsa.generatePrivateKey("x");
    }
    assert.throws(f2, /Expected a 32-bit integer in args\[0]\./);

    function f3() {
        rsa.generatePrivateKey(10);
    }
    assert.throws(f3, /Missing args\[1]\./);

    function f4() {
        rsa.generatePrivateKey(20, "x");
    }
    assert.throws(f4, /Expected a 32-bit integer in args\[1]\./);

    function f5() {
        rsa.generatePrivateKey(512, 2);
    }
    assert.throws(f5, /Expected odd exponent\./);

    function f6() {
        rsa.generatePrivateKey(512, 0);
    }
    assert.throws(f6, /Expected positive exponent\./);

    function f7() {
        rsa.generatePrivateKey(511, 1);
    }
    assert.throws(f7, /Expected modulus bit count >= 512\./);

    // Use the original f1(), above, for this test.
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Key already set\./);
}

function test_sign() {
    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var buf = new Buffer(fixture.FAKE_SHA256_TO_SIGN, fixture.HEX);
    var sig = rsa.sign(textToNid(fixture.SHA256), buf);

    assert.equal(sig.toString(fixture.HEX), fixture.FAKE_SHA256_SIGNATURE);

    buf = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
    sig = rsa.sign(textToNid(fixture.SHA256), buf);

    assert.equal(sig.toString(fixture.HEX), fixture.PLAINTEXT_SHA256_SIGNATURE);
}

function test_fail_sign() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.sign();
    }

    assert.throws(f1, /Key not yet set\./);

    rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Expected a private key\./);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    function f2() {
        rsa.sign("x", "x");
    }
    assert.throws(f2, /Expected a 32-bit integer in args\[0]\./);

    function f3() {
        rsa.sign(1, "x");
    }
    assert.throws(f3, /Expected a Buffer in args\[1]\./);

    function f4() {
        rsa.sign(1, new Buffer(2048));
    }
    assert.throws(f4, /too big/);

    function f5() {
        rsa.sign(99999, new Buffer(16));
    }
    assert.throws(f5, /unknown algorithm/);
}

function test_verify() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);

    var hash = new Buffer(fixture.FAKE_SHA256_TO_SIGN, fixture.HEX);
    var sig = new Buffer(fixture.FAKE_SHA256_SIGNATURE, fixture.HEX);
    assert.equal(rsa.verify(textToNid(fixture.SHA256), hash, sig), true);

    // Private keys should be able to verify too.
    hash = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
    sig = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
    assert.equal(rsa.verify(textToNid(fixture.SHA256), hash, sig), true);

    // Signature mismatch should return false (and not, e.g., throw).
    hash = new Buffer(fixture.FAKE_SHA256_TO_SIGN, fixture.HEX);
    sig = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
    assert.equal(rsa.verify(textToNid(fixture.SHA256), hash, sig), false);
}

function test_fail_verify() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.verify();
    }

    assert.throws(f1, /Key not yet set\./);

    rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);

    function f2() {
        rsa.verify("x", "x", "x");
    }
    assert.throws(f2, /Expected a 32-bit integer in args\[0]\./);

    function f3() {
        rsa.verify(1, "x", "x");
    }
    assert.throws(f3, /Expected a Buffer in args\[1]\./);

    function f4() {
        rsa.verify(1, new Buffer(16), "x");
    }
    assert.throws(f4, /Expected a Buffer in args\[2]\./);

    function f5() {
        var hash = new Buffer(10);
        var sig = new Buffer(5);
        hash.fill(0);
        sig.fill(0);
        rsa.verify(1, hash, sig);
    }
    assert.throws(f5, /wrong signature length/);

    function f6() {
        var buf = new Buffer(256);
        buf.fill(0);
        rsa.verify(1, new Buffer(10), buf);
    }
    assert.throws(f6, /padding_check/);

    function f7() {
        var hash = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
        var sig = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
        rsa.verify(textToNid(fixture.SHA1), hash, sig);
    }
    assert.throws(f7, /algorithm mismatch/);

    function f8() {
        var hash = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
        var sig = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
        rsa.verify(1234567, hash, sig);
    }
    assert.throws(f8, /algorithm mismatch/);
}

function test_textToNid() {
    // I don't think you can count on the return values being anything
    // other than integer values and that aliases should return equal
    // values.

    function verifyInt(value) {
        if (typeof value !== "number") {
            throw new Error("Not a number: " + value);
        }

        if (value !== Math.floor(value)) {
            throw new Error("Not an integer: " + value);
        }
    }

    verifyInt(textToNid("aes-128-ecb"));
    verifyInt(textToNid("md5"));
    verifyInt(textToNid("rsa"));
    verifyInt(textToNid("sha1"));
    verifyInt(textToNid("sha256"));
    verifyInt(textToNid("RSA-SHA256"));
    verifyInt(textToNid("pkcs7"));

    assert.equal(textToNid("RSA-SHA256"), textToNid("sha256WithRSAEncryption"));
    assert.equal(textToNid("AES-128-ECB"), textToNid("aes-128-ecb"));
}

function test_fail_textToNid() {

    function f1() {
        textToNid();
    }
    assert.throws(f1, /Missing args\[0\]/);

    function f2() {
        textToNid(123);
    }
    assert.throws(f2, /Expected a string in args\[0\]/);

    function f3() {
        textToNid("blort");
    }
    assert.throws(f3, /asn1/);
}

function _test_PSSPadding(slen)
{
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);

    var nid = textToNid(fixture.SHA256);
    var hash = new Buffer(fixture.FAKE_SHA256_TO_SIGN, fixture.HEX);
    var em = rsa.addPSSPadding(nid, hash, slen);

    assert.equal(rsa.verifyPSSPadding(nid, hash, em, slen), true);
}

function test_PSSPadding()
{
    _test_PSSPadding(ursaNative.RSA_PKCS1_SALT_LEN_HLEN);
    _test_PSSPadding(ursaNative.RSA_PKCS1_SALT_LEN_RECOVER);

    var rsa = new RsaWrap();
    rsa.createPublicKeyFromComponents(
        new Buffer(fixture.PSS_MODULUS_HEX, fixture.HEX),
        new Buffer(fixture.EXPONENT_HEX, fixture.HEX));

    var tvhash = new Buffer(fixture.PSS_MHASH_HEX, fixture.HEX);
    var tvem = new Buffer(fixture.PSS_EM_HEX, fixture.HEX);

    assert.equal(rsa.verifyPSSPadding(
            textToNid(fixture.SHA1), tvhash, tvem, ursaNative.RSA_PKCS1_SALT_LEN_HLEN), true);
}

function test_fail_PSSPadding()
{
    var rsa = new RsaWrap();

    function f1() {
        rsa.addPSSPadding();
    }
    assert.throws(f1, /Key not yet set\./);
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Not enough args\./);

    var nid = textToNid(fixture.SHA256);
    var hash = new Buffer(fixture.FAKE_SHA256_TO_SIGN, fixture.HEX);
    var slen = ursaNative.RSA_PKCS1_SALT_LEN_HLEN;

    function f2() {
        rsa.addPSSPadding("x", hash, slen);
    }
    assert.throws(f2, /Expected a 32-bit integer in args\[0\]\./);

    function f3() {
        rsa.addPSSPadding(nid, "x", slen);
    }
    assert.throws(f3, /Expected a Buffer in args\[1\]\./);

    function f4() {
        rsa.addPSSPadding(nid, hash, "x");
    }
    assert.throws(f4, /Expected a 32-bit integer in args\[2\]\./);

    function f5() {
        rsa.addPSSPadding(nid, hash, 1000000);
    }
    assert.throws(f5, /data too large for key size/);

    function f6() {
        rsa.addPSSPadding(nid, hash, -3);
    }
    assert.throws(f6, /salt length check failed/);

    var em = rsa.addPSSPadding(nid, hash, slen);

    function f7() {
        rsa.verifyPSSPadding();
    }
    assert.throws(f7, /Not enough args\./);

    function f8() {
        rsa.verifyPSSPadding("x", hash, em, slen);
    }
    assert.throws(f8, /Expected a 32-bit integer in args\[0\]\./);

    function f9() {
        rsa.verifyPSSPadding(nid, "x", em, slen);
    }
    assert.throws(f9, /Expected a Buffer in args\[1\]\./);

    function f10() {
        rsa.verifyPSSPadding(nid, hash, "x", slen);
    }
    assert.throws(f10, /Expected a Buffer in args\[2\]\./);

    function f11() {
        rsa.verifyPSSPadding(nid, hash, em, "x");
    }
    assert.throws(f11, /Expected a 32-bit integer in args\[3\]\./);

    function f12() {
        rsa.verifyPSSPadding(nid, hash, em, 1000000);
    }
    assert.throws(f12, /data too large/);

    function f13() {
        rsa.verifyPSSPadding(nid, hash, em, -3);
    }
    assert.throws(f13, /salt length check failed/);

    em[em.length-1] ^= 2;

    function f14()  {
        rsa.verifyPSSPadding(nid, hash, em, slen);
    }
    assert.throws(f14, /last octet invalid/);

    em[em.length-1] ^= 2;
    em[1] ^= 2;
    assert.throws(f14, /salt length recovery failed/);
}

/*
 * Main test script
 */

function test() {
    test_new();

    test_getPrivateExponent();
    test_setPrivateKeyPem();
    test_fail_setPrivateKeyPem();
    test_setPublicKeyPem();
    test_fail_setPublicKeyPem();

    test_getExponent();
    test_fail_getExponent();
    test_getModulus();
    test_fail_getModulus();
    test_getPrivateKeyPem();
    test_fail_getPrivateKeyPem();
    test_getPublicKeyPem();
    test_fail_getPublicKeyPem();

    test_privateDecrypt();
    test_fail_privateDecrypt();
    test_publicEncrypt();
    test_fail_publicEncrypt();

    test_privateEncrypt();
    test_fail_privateEncrypt();
    test_publicDecrypt();
    test_fail_publicDecrypt();

    test_generatePrivateKey();
    test_fail_generatePrivateKey();

    test_sign();
    test_fail_sign();
    test_verify();
    test_fail_verify();

    test_textToNid();
    test_fail_textToNid();

    test_PSSPadding();
    test_fail_PSSPadding();
}

module.exports = {
    test: test
};
