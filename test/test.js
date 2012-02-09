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

function createPublicKey() {
    return ursa.pemToPublicKey(fixture.PUBLIC_KEY);
}

function createPrivateKey() {
    return ursa.pemToPrivateKey(fixture.PRIVATE_KEY);
}

function createPassPrivateKey() {
    return ursa.pemToPrivateKey(fixture.PRIVATE_KEY, fixture.PASSWORD);
}


/*
 * Test functions
 */

function testBasics() {
    createPublicKey();
    createPrivateKey();
    createPassPrivateKey();
}

/*
 * Main test script
 */

// Test the native code (reasonably) directly.
require("./native").test();

testBasics();

console.log("All tests pass!");