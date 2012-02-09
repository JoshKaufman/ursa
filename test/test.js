// Copyright 2012 The Obvious Corporation.

/*
 * Tests of ursa
 */

/*
 * Modules used
 */

var assert = require('assert');
var fs     = require('fs');

var ursa = require('../lib/ursa');


/*
 * Variable definitions
 */

var PUBKEY_FILE_NAME       = __dirname + "/blort.pub";
var PRIVKEY_FILE_NAME      = __dirname + "/blort.pem";
var PASS_PRIVKEY_FILE_NAME = __dirname + "/blort-pass.pem";

var PASSWORD = "biscuits";

/*
 * Helper functions
 */

function createPublicKey() {
    var file = fs.readFileSync(PUBKEY_FILE_NAME);
    return ursa.pemToPublicKey(file);
}

function createPrivateKey() {
    var file = fs.readFileSync(PRIVKEY_FILE_NAME);
    return ursa.pemToPrivateKey(file);
}

function createPassPrivateKey() {
    var file = fs.readFileSync(PRIVKEY_FILE_NAME);
    return ursa.pemToPrivateKey(file, PASSWORD);
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

testBasics();

console.log("All tests pass!");