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

function test_toPublicSsh(key) {
    var keyString = fixture.SSH_PUBLIC_KEY.toString(fixture.BASE64);
    var result = key.toPublicSsh().toString(fixture.BASE64);
    assert.equal(result, keyString);

    result = key.toPublicSsh(fixture.BASE64);
    assert.equal(result, keyString);
}

function test_toPublicSshFingerprint(key) {
    var result = key.toPublicSshFingerprint().toString(fixture.HEX);
    assert.equal(result, fixture.SSH_PUBLIC_KEY_FINGERPRINT_HEX);

    result = key.toPublicSshFingerprint(fixture.HEX);
    assert.equal(result, fixture.SSH_PUBLIC_KEY_FINGERPRINT_HEX);
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

    encoded = key.encrypt(fixture.PLAINTEXT, undefined, fixture.HEX);
    decoded = privKey.decrypt(encoded, fixture.HEX, fixture.UTF8);
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

function test_verify(key) {
    assert.equal(key.verify(fixture.SHA256, fixture.PLAINTEXT_SHA256,
                            fixture.PLAINTEXT_SHA256_SIGNATURE,
                            fixture.HEX), true);

    var hash = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
    var sig = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
    assert.equal(key.verify(fixture.SHA256, hash, sig), true);
}

function test_hashAndVerify(key) {
    assert.equal(key.hashAndVerify(fixture.SHA256,
                                   new Buffer(fixture.PLAINTEXT, fixture.UTF8),
                                   fixture.PLAINTEXT_SHA256_SIGNATURE,
                                   fixture.HEX),
                 true);
}

function testPublicKeyMethods(key) {
    test_getExponent(key);
    test_getModulus(key);
    test_toPublicPem(key);
    test_toPublicSsh(key);
    test_toPublicSshFingerprint(key);
    test_encrypt(key);
    test_publicDecrypt(key);
    test_verify(key);
    test_hashAndVerify(key);
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

    encoded = key.privateEncrypt(fixture.PLAINTEXT, undefined, fixture.HEX);
    assert.equal(encoded, fixture.PUBLIC_CIPHERTEXT_HEX);
}

function test_sign(key) {
    var sig = key.sign(fixture.SHA256,
                       fixture.PLAINTEXT_SHA256, fixture.HEX,
                       fixture.BASE64);
    sig = new Buffer(sig, fixture.BASE64);
    assert.equal(sig.toString(fixture.HEX), fixture.PLAINTEXT_SHA256_SIGNATURE);

    var buf = new Buffer(fixture.PLAINTEXT_SHA256, fixture.HEX);
    sig = key.sign(fixture.SHA256, buf, undefined, fixture.HEX);
    assert.equal(sig, fixture.PLAINTEXT_SHA256_SIGNATURE);
}

function test_hashAndSign(key) {
    var sig = key.hashAndSign(fixture.SHA256, fixture.PLAINTEXT,
                              fixture.UTF8, fixture.HEX);
    assert.equal(sig, fixture.PLAINTEXT_SHA256_SIGNATURE);
}

function testPrivateKeyMethods(key) {
    test_toPrivatePem(key);
    test_decrypt(key);
    test_privateEncrypt(key);
    test_hashAndSign(key);
    test_sign(key);
}


/*
 * Test functions
 */

function testBasics() {
    ursa.createPublicKey(fixture.PUBLIC_KEY);
    ursa.createPrivateKey(fixture.PRIVATE_KEY);
    ursa.createPrivateKey(fixture.PASS_PRIVATE_KEY, fixture.PASSWORD);
    ursa.generatePrivateKey(512);

    ursa.createPublicKey(fixture.PUBLIC_KEY.toString(fixture.UTF8));
    ursa.createPrivateKey(fixture.PRIVATE_KEY.toString(fixture.BASE64),
                          undefined, fixture.BASE64);
}

function testTypes() {
    var pub = ursa.createPublicKey(fixture.PUBLIC_KEY);
    var priv = ursa.createPrivateKey(fixture.PRIVATE_KEY);
    var msg;
    
    msg = "Problem with isKey()";
    assert.equal(ursa.isKey(pub),       true,  msg);
    assert.equal(ursa.isKey(priv),      true,  msg);
    assert.equal(ursa.isKey(undefined), false, msg);
    assert.equal(ursa.isKey("x"),       false, msg);

    msg = "Problem with isPublicKey()";
    assert.equal(ursa.isPublicKey(pub),       true,  msg);
    assert.equal(ursa.isPublicKey(priv),      false, msg);
    assert.equal(ursa.isPublicKey(undefined), false, msg);
    assert.equal(ursa.isPublicKey("x"),       false, msg);

    msg = "Problem with isPrivateKey()";
    assert.equal(ursa.isPrivateKey(pub),       false, msg);
    assert.equal(ursa.isPrivateKey(priv),      true,  msg);
    assert.equal(ursa.isPrivateKey(undefined), false, msg);
    assert.equal(ursa.isPrivateKey("x"),       false, msg);
}

function test_fail_createPublicKey() {
    // This is mostly tested at the native level. This just tests the
    // extra failures added at the high level.
    function f1() {
        ursa.createPublicKey(fixture.PRIVATE_KEY);
    }
    assert.throws(f1, /Not a public key\./);
}

function test_fail_createPrivateKey() {
    // This is mostly tested at the native level. This just tests the
    // extra failures added at the high level.
    function f1() {
        ursa.createPrivateKey(fixture.PUBLIC_KEY);
    }
    assert.throws(f1, /Not a private key\./);
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

function testSshFingerprint() {
    var key = fixture.SSH_PUBLIC_KEY;
    var finger = ursa.sshFingerprint(fixture.SSH_PUBLIC_KEY);
    assert.equal(finger.toString(fixture.HEX),
                 fixture.SSH_PUBLIC_KEY_FINGERPRINT_HEX);

    finger = ursa.sshFingerprint(fixture.SSH_PUBLIC_KEY, undefined,
                                 fixture.HEX);
    assert.equal(finger, fixture.SSH_PUBLIC_KEY_FINGERPRINT_HEX);

    finger = ursa.sshFingerprint(
        fixture.SSH_PUBLIC_KEY.toString(fixture.BASE64), 
        fixture.BASE64, fixture.HEX);
    assert.equal(finger, fixture.SSH_PUBLIC_KEY_FINGERPRINT_HEX);
}

function testSigner() {
    var key = ursa.createPrivateKey(fixture.PRIVATE_KEY);
    var signer = ursa.createSigner(fixture.SHA256);

    signer.update(fixture.PLAINTEXT, fixture.UTF8);

    var sig = signer.sign(key, fixture.HEX);

    assert.equal(sig, fixture.PLAINTEXT_SHA256_SIGNATURE);
}

function testVerifier() {
    var key = ursa.createPublicKey(fixture.PUBLIC_KEY);
    var verifier = ursa.createVerifier(fixture.SHA256);
    verifier.update(fixture.PLAINTEXT, fixture.UTF8);
    assert.equal(verifier.verify(key, fixture.PLAINTEXT_SHA256_SIGNATURE,
                                 fixture.HEX),
                 true);

    var verifier = ursa.createVerifier(fixture.SHA256);
    verifier.update(new Buffer(fixture.PLAINTEXT, fixture.UTF8));
    var sigBuf = new Buffer(fixture.PLAINTEXT_SHA256_SIGNATURE, fixture.HEX);
    assert.equal(verifier.verify(key, sigBuf), true);
}

/*
 * Main test script
 */

// Test the native code (reasonably) directly.
require("./native").test();

testBasics();
testTypes();
test_fail_createPublicKey();
test_fail_createPrivateKey();
testPublicKey();
testPrivateKey();
testGeneratedKey();
testSshFingerprint();
testSigner();
testVerifier();

console.log("All tests pass!");