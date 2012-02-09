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

/*
 * Main test script
 */

function test() {
    test_new();
    test_setPrivateKeyPem();
    test_fail_setPrivateKeyPem();
    test_setPublicKeyPem();
    test_fail_setPublicKeyPem();
}

module.exports = {
    test: test
};
