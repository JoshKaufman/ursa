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

function test_fail_setPublicKeyPem() {
    var rsa = new RsaWrap();

    function f1() {
        rsa.setPublicKeyPem();
    }

    assert.throws(f1, /Missing args/);

    function f2() {
        rsa.setPublicKeyPem("x");
    }

    assert.throws(f2, /Expected a Buffer in args/);

    function f3() {
        rsa.setPublicKeyPem(new Buffer("x"));
    }

    assert.throws(f3, /no start line/);
}

function test_setPublicKeyPem() {
    var rsa = new RsaWrap();
    rsa.setPublicKeyPem(fixture.PUBLIC_KEY);
}


/*
 * Main test script
 */

function test() {
    test_new();
    test_setPublicKeyPem();
    test_fail_setPublicKeyPem();
}

module.exports = {
    test: test
};
