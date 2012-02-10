// Copyright 2012 The Obvious Corporation.

/*
 * Tests of ursa
 */

/*
 * Modules used
 */

var assert = require("assert");

var fixture = require("./fixture");
var ursa =    fixture.ursa;


/*
 * Helper functions
 */

function test_getExponent(key) {
    var buf = key.getExponent();
    assert.equal(buf.toString(fixture.HEX), fixture.EXPONENT_HEX);

    var result = key.getExponent(fixture.HEX);
    assert.equal(result, fixture.EXPONENT_HEX);

    result = key.getExponent(fixture.BASE64);
    assert.equal(result, buf.toString(fixture.BASE64));

    result = key.getExponent(fixture.BINARY);
    assert.equal(result, buf.toString(fixture.BINARY));

    result = key.getExponent(fixture.UTF8);
    assert.equal(result, buf.toString(fixture.UTF8));
}

function test_getModulus(key) {
    var buf = key.getModulus();
    assert.equal(buf.toString(fixture.HEX), fixture.MODULUS_HEX);

    var result = key.getModulus(fixture.HEX);
    assert.equal(result, fixture.MODULUS_HEX);

    result = key.getModulus(fixture.BASE64);
    assert.equal(result, buf.toString(fixture.BASE64));

    result = key.getModulus(fixture.BINARY);
    assert.equal(result, buf.toString(fixture.BINARY));

    result = key.getModulus(fixture.UTF8);
    assert.equal(result, buf.toString(fixture.UTF8));
}

function test_toPublicPem(key) {
    var keyString = fixture.PUBLIC_KEY.toString(fixture.UTF8);
    var result = key.toPublicPem().toString(fixture.UTF8);
    assert.equal(result, keyString);

    result = key.toPublicPem(fixture.UTF8);
    assert.equal(result, keyString);
}

function test_encrypt(key) {
    // The sanest way to test this is to do a round trip.
    var privKey = ursa.createPrivateKey(fixture.PRIVATE_KEY)
    var encoded = key.encrypt(new Buffer(fixture.PLAINTEXT, fixture.UTF8));
    var decoded = privKey.decrypt(encoded, undefined, fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    encoded = key.encrypt(fixture.PLAINTEXT, fixture.UTF8, fixture.BASE64);
    decoded = privKey.decrypt(encoded, fixture.BASE64, fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_publicDecrypt(key) {
    var encoded = new Buffer(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX);
    var decoded = key.publicDecrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    decoded = key.publicDecrypt(fixture.PUBLIC_CIPHERTEXT_HEX, fixture.HEX,
                                fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function testPublicKeyMethods(key) {
    test_getExponent(key);
    test_getModulus(key);
    test_toPublicPem(key);
    test_encrypt(key);
    test_publicDecrypt(key);
}

function test_toPrivatePem(key) {
    var keyString = fixture.PRIVATE_KEY.toString(fixture.UTF8);
    var result = key.toPrivatePem().toString(fixture.UTF8);
    assert.equal(result, keyString);

    result = key.toPrivatePem(fixture.UTF8);
    assert.equal(result, keyString);
}

function test_decrypt(key) {
    var encoded = new Buffer(fixture.PRIVATE_CIPHERTEXT_HEX, fixture.HEX);
    var decoded = key.decrypt(encoded).toString(fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);

    decoded = key.decrypt(fixture.PRIVATE_CIPHERTEXT_HEX, fixture.HEX,
                          fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}

function test_privateEncrypt(key) {
    var encoded = key.privateEncrypt(
        new Buffer(fixture.PLAINTEXT, fixture.UTF8)).toString(fixture.HEX);
    assert.equal(encoded, fixture.PUBLIC_CIPHERTEXT_HEX);

    encoded = key.privateEncrypt(fixture.PLAINTEXT, fixture.UTF8, fixture.HEX);
    assert.equal(encoded, fixture.PUBLIC_CIPHERTEXT_HEX);
}

function testPrivateKeyMethods(key) {
    test_toPrivatePem(key);
    test_decrypt(key);
    test_privateEncrypt(key);
}


/*
 * Test functions
 */

function testBasics() {
    ursa.createPublicKey(fixture.PUBLIC_KEY);
    ursa.createPrivateKey(fixture.PRIVATE_KEY);
    ursa.createPrivateKey(fixture.PRIVATE_KEY, fixture.PASSWORD);
    ursa.generatePrivateKey(512);
}

function testPublicKey() {
    var key = ursa.createPublicKey(fixture.PUBLIC_KEY);
    testPublicKeyMethods(key);
}

function testPrivateKey() {
    var key = ursa.createPrivateKey(fixture.PRIVATE_KEY);
    testPublicKeyMethods(key);
    testPrivateKeyMethods(key);
}

function testGeneratedKey() {
    // Just do a round trip. If that works, then it's safe to believe
    // the native tests (which are more comprehensive).
    var key = ursa.generatePrivateKey();
    var encoded = key.encrypt(fixture.PLAINTEXT, fixture.UTF8);
    var decoded = key.decrypt(encoded, undefined, fixture.UTF8);
    assert.equal(decoded, fixture.PLAINTEXT);
}


/*
 * Main test script
 */

// Test the native code (reasonably) directly.
require("./native").test();

testBasics();
testPublicKey();
testPrivateKey();
testGeneratedKey();

console.log("All tests pass!");