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
    var keyStr = fixture.PRIVATE_KEY.toString(fixture.UTF8);

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

    // test_generatePrivateKey();

    // test_privateDecrypt()
    // test_privateEncrypt()
    // test_publicDecrypt()
    // test_publicEncrypt()
}

module.exports = {
    test: test
};
