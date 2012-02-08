// Copyright 2012 The Obvious Corporation.

/*
 * Tests of rsab
 */

/*
 * Modules used
 */

var assert = require('assert');
var fs     = require('fs');

var rsab = require('../lib/rsab');


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
    return rsab.pemToPublicKey(file);
}

function createPrivateKey() {
    var file = fs.readFileSync(PRIVKEY_FILE_NAME);
    return rsab.pemToPrivateKey(file);
}

function createPassPrivateKey() {
    var file = fs.readFileSync(PRIVKEY_FILE_NAME);
    return rsab.pemToPrivateKey(file, PASSWORD);
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