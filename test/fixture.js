// Copyright 2012 The Obvious Corporation.

/*
 * Common fixture for use across tests
 */

/*
 * Modules used
 */

var fs     = require("fs");

var ursa = require("../lib/ursa");
var ursaNative = require("../bin/ursaNative");


/*
 * Variable definitions
 */

var BASE64 = "base64";
var BINARY = "binary";
var HEX    = "hex";
var UTF8   = "utf8";

var PASS_PRIVATE_KEY = fs.readFileSync(__dirname + "/blort-pass.pem");
var PRIVATE_KEY = fs.readFileSync(__dirname + "/blort.pem");
var PUBLIC_KEY = fs.readFileSync(__dirname + "/blort.pub");

var PASSWORD = new Buffer("biscuits", UTF8);

var EXPONENT_HEX = "010001";
var MODULUS_HEX = "123"; // FIXME

/*
 * Exported bindings
 */

module.exports = {
    BASE64: BASE64,
    BINARY: BINARY,
    HEX:    HEX,
    UTF8:   UTF8,
    
    EXPONENT_HEX:     EXPONENT_HEX,
    MODULUS_HEX:      MODULUS_HEX,
    PASSWORD:         PASSWORD,
    PASS_PRIVATE_KEY: PASS_PRIVATE_KEY,
    PRIVATE_KEY:      PRIVATE_KEY,
    PUBLIC_KEY:       PUBLIC_KEY,

    RsaWrap: ursaNative.RsaWrap,

    ursa:       ursa,
    ursaNative: ursaNative
};
