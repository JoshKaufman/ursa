// Copyright 2012 The Obvious Corporation.

/*
 * Tests of the underlying RsaWrap class.
 */

/*
 * Modules used
 */

var assert = require("assert");

var fixture = require("./fixture");
var RsaWrap = fixture.RsaWrap;


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

function test_getPrivateKeyPem() {
    var keyStr = fixture.PRIVATE_KEY.toString(fixture.UTF8);

    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var pem = rsa.getPrivateKeyPem().toString(fixture.UTF8);
    assert.equal(pem, keyStr);
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
    assert.equal(pem, keyStr);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    pem = rsa.getPublicKeyPem().toString(fixture.UTF8);
    assert.equal(pem, keyStr);
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
    var decoded = rsa.privateDecrypt(encoded).toString(fixture.UTF8);
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
        rsa.privateDecrypt("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.privateDecrypt(new Buffer("x"));
    }
    assert.throws(f3, /decoding error/);
}

function test_publicEncrypt() {
    // No other reasonable way to test this than to do a round trip.
    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var priv = new RsaWrap();
    priv.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var encoded = rsa.publicEncrypt(plainBuf);
    var decoded = priv.privateDecrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    encoded = priv.publicEncrypt(plainBuf);
    decoded = priv.privateDecrypt(encoded).toString(fixture.UTF8);
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
        rsa.publicEncrypt("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.publicEncrypt(new Buffer(2048));
    }
    assert.throws(f3, /too large/);
}

function test_privateEncrypt() {
    var rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);

    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var encoded = rsa.privateEncrypt(plainBuf).toString(fixture.HEX);

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
        rsa.privateEncrypt("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.privateEncrypt(new Buffer(2048));
    }
    assert.throws(f3, /too large/);
}

function test_publicDecrypt() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    var encoded = new Buffer(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX);
    var decoded = rsa.publicDecrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    rsa = new RsaWrap();
    rsa.setPrivateKeyPem(fixture.PRIVATE_KEY);
    encoded = new Buffer(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX);
    decoded = rsa.publicDecrypt(encoded).toString(fixture.UTF8);
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
        rsa.publicDecrypt("x");
    }
    assert.throws(f2, /Expected a Buffer in args\[0]\./);

    function f3() {
        rsa.publicDecrypt(new Buffer("x"));
    }
    assert.throws(f3, /padding_check/);
}

function test_generatePrivateKey() {
    var rsa = new RsaWrap();
    rsa.generatePrivateKey(512, 65537);

    // Do a round trip check.
    var plainBuf = new Buffer(fixture.PLAINTEXT, fixture.UTF8);
    var encoded = rsa.publicEncrypt(plainBuf);
    var decoded = rsa.privateDecrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    // Extract the public key, and try using it for a round trip.
    var pubKey = new RsaWrap();
    pubKey.setPublicKeyPem(rsa.getPublicKeyPem());
    encoded = pubKey.publicEncrypt(plainBuf);
    decoded = rsa.privateDecrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
    
    // Similarly, try decoding with an extracted private key.
    var privKey = new RsaWrap();
    privKey.setPrivateKeyPem(rsa.getPrivateKeyPem());
    decoded = privKey.privateDecrypt(encoded).toString(fixture.UTF8);
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
        rsa.generatePrivateKey(512, 0);
    }
    assert.throws(f5, /Expected odd exponent\./);

    function f6() {
        rsa.generatePrivateKey(0, 1);
    }
    assert.throws(f6, /key size too small/);

    // Use the original f1(), above, for this test.
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
    assert.throws(f1, /Key already set\./);
}


/*
 * Main test script
 */

function test() {
    test_new();

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
}

module.exports = {
    test: test
};
