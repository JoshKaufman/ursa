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
var MODULUS_HEX =
    "ae0a2fd0a1d56253ad4b5e7f5883b41e9cfd348b964221fff55b82aa3127b0c2" +
    "5d651db436cc623428cc4e3397b65f23086140a7c7f26f9a5e4fb425a78c5993" +
    "2ea875ec8511ce99f50227c91495068ce546861285e7d0e8948f15a17d93e158" +
    "14dff1cf42d81d9c19096fabefc75057d646281413eb5125f0d8ab8a2a8aab54" +
    "81662108ee34f5f09d22e87d6a155024919732cf7bfce7fcae74f502d70045c3" +
    "37e4f7227d3bc6e93651a89f1943a10297c474bcc95d79753a80028795cac06a" +
    "424d7f3620d0b8424c6ebab771f0e5974b1cb2755e734770214358f546acc6b6" +
    "cfa70934d1c7b9e2e5a3c1897fb10f803af2998495db24511f2b2162f1fd8475";

var PLAINTEXT = "Muffins are tasty.";
var PRIVATE_CIPHERTEXT_HEX = "1234"; // FIXME
var PUBLIC_CIPHERTEXT_HEX = "1234"; // FIXME

/*
 * Exported bindings
 */

module.exports = {
    BASE64: BASE64,
    BINARY: BINARY,
    HEX:    HEX,
    UTF8:   UTF8,
    
    EXPONENT_HEX:           EXPONENT_HEX,
    MODULUS_HEX:            MODULUS_HEX,
    PASSWORD:               PASSWORD,
    PASS_PRIVATE_KEY:       PASS_PRIVATE_KEY,
    PLAINTEXT:              PLAINTEXT,
    PRIVATE_CIPHERTEXT_HEX: PRIVATE_CIPHERTEXT_HEX,
    PRIVATE_KEY:            PRIVATE_KEY,
    PUBLIC_CIPHERTEXT_HEX:  PUBLIC_CIPHERTEXT_HEX,
    PUBLIC_KEY:             PUBLIC_KEY,

    RsaWrap: ursaNative.RsaWrap,

    ursa:       ursa,
    ursaNative: ursaNative
};
