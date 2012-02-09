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
var PRIVATE_CIPHERTEXT_HEX =
    "98a96084dc8dfad2c4e604dc20def71acbf784b8b34ecafeb2840e238ac8031c" +
    "7559004fa8337d20889b8a582af4f7d3707ab41d0a81487f0d80fb82be49537c" +
    "2b9cd8dbb3b772fe0306ff9b4b99faa7cc26d5c04b1e8e79505bac1e8f2cdad2" +
    "d3d8680eee3c16db8742b61935fca9679070d278f988ce4d414ab49a544c9088" +
    "17a0d340a41384f4b8d826e41031ddcd3f72c29dec2fee0355a8203ea0d381a1" +
    "a0f0969804d4968fb2e6220db5cf02e2c2200ff9d0a5a5037ac859a55c005ecc" +
    "52ce194a6a9624c71547c96cf90d911caa4097f9cdfded71d23c9f8f5551188c" +
    "8326357d54224ab25b9f29c1efdbc960a0968e4c9027cd507ffadd8dff93256c";
var PUBLIC_CIPHERTEXT_HEX =
    "16b5e95a02db09e95bb5419998b3c5f450571578be271602828740242236e6aa" +
    "0bce325d6b9a681038c864e0877a3e68e20329a3602829128385f182a20f06c7" +
    "6f4c82f4f58481ff19ac2db9fd2b6b097047f741fa81a6c6a50b33259f3458b7" +
    "5adcc40cc7ce71654d69936f1f77bdc684d069615ffeb71566487cdd62c55bc9" +
    "5688452cb1857c91fd6cc0c7506f974ff4274a88b768f5e332b64933cabc9ef5" +
    "2204e62f8682c177d5c7aa6e94e66125ad7a42eb9352e6af1ea6478e92599454" +
    "65bc54fed2b45317713f7caa98cbd28a14c4c7fabe8689e735985e3fa6bd7ca8" +
    "bda58bee1b3cba48cb0d1508c79c23d48413b3dc296aabf5291288783ff037ef";

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
