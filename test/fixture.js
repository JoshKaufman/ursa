// Copyright 2012 The Obvious Corporation.

/*
 * Common fixture for use across tests
 */

/*
 * Modules used
 */

"use strict";

var fs = require("fs");

var ursa       = require("../lib/ursa");
var ursaNative = require("bindings")("ursaNative");


/*
 * Variable definitions
 */

var BASE64 = "base64";
var BINARY = "binary";
var HEX    = "hex";
var SHA1   = "sha1";
var SHA256 = "sha256";
var UTF8   = "utf8";
var DES_EDE3_CBC = "des-ede3-cbc";

var PASS_PRIVATE_KEY = fs.readFileSync(__dirname + "/blort-pass.pem");
var PRIVATE_KEY = fs.readFileSync(__dirname + "/blort.pem");
var PUBLIC_KEY = fs.readFileSync(__dirname + "/blort.pub");
var SSH_PUBLIC_KEY_FILE = fs.readFileSync(__dirname + "/blort.sshpub");
var PRIVATE_KEY_2 = fs.readFileSync(__dirname + "/zorch.pem");
var PUBLIC_KEY_2 = fs.readFileSync(__dirname + "/zorch.pub");
var PRIVATE_KEY_2 = fs.readFileSync(__dirname + "/zorch.pem");
var PRIVATE_KEY_3 = fs.readFileSync(__dirname + "/another_zorch.pem");

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
var PLAINTEXT_PADDED = 
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0" + "Muffins are tasty.";
var PRIVATE_CIPHERTEXT_HEX =
    "98a96084dc8dfad2c4e604dc20def71acbf784b8b34ecafeb2840e238ac8031c" +
    "7559004fa8337d20889b8a582af4f7d3707ab41d0a81487f0d80fb82be49537c" +
    "2b9cd8dbb3b772fe0306ff9b4b99faa7cc26d5c04b1e8e79505bac1e8f2cdad2" +
    "d3d8680eee3c16db8742b61935fca9679070d278f988ce4d414ab49a544c9088" +
    "17a0d340a41384f4b8d826e41031ddcd3f72c29dec2fee0355a8203ea0d381a1" +
    "a0f0969804d4968fb2e6220db5cf02e2c2200ff9d0a5a5037ac859a55c005ecc" +
    "52ce194a6a9624c71547c96cf90d911caa4097f9cdfded71d23c9f8f5551188c" +
    "8326357d54224ab25b9f29c1efdbc960a0968e4c9027cd507ffadd8dff93256c";
var PRIVATE_OLD_PAD_CIPHER_HEX =
    "69d1c385929fc00f89aa98ae9cd8529afe884b581505acdcd4ceaa10bfda9adc" +
    "79c472dd7e35bcc94f1146459c6a8d96e572116c7a62f1da5dd18cdb8f81e72b" +
    "4a4649f40470e88c11b04fdf72e48c6adb44c41edc0c4c56074a041c03017f72" +
    "f66a000066a4dbe888119c83f79e7cb8f667f0af1af41cf4adf21320fada9355" +
    "6d056a2fdb1f5a9f5708e096a7408a115efa14f0e2f94feaa32322aa4af9c97a" +
    "438d205f62317020e657c5057227a3d7e60a6a6658781cf41b0820988a4f9e8e" +
    "b947c424248d231c3e43c711b0c4a4342a0fa484d0e3ded231a695250f4dafcf" +
    "f9e94d02e3f74d4c509cfae24b8615e619805c9cdc9e85faed7d706dd6891383";
var PUBLIC_CIPHERTEXT_HEX =
    "16b5e95a02db09e95bb5419998b3c5f450571578be271602828740242236e6aa" +
    "0bce325d6b9a681038c864e0877a3e68e20329a3602829128385f182a20f06c7" +
    "6f4c82f4f58481ff19ac2db9fd2b6b097047f741fa81a6c6a50b33259f3458b7" +
    "5adcc40cc7ce71654d69936f1f77bdc684d069615ffeb71566487cdd62c55bc9" +
    "5688452cb1857c91fd6cc0c7506f974ff4274a88b768f5e332b64933cabc9ef5" +
    "2204e62f8682c177d5c7aa6e94e66125ad7a42eb9352e6af1ea6478e92599454" +
    "65bc54fed2b45317713f7caa98cbd28a14c4c7fabe8689e735985e3fa6bd7ca8" +
    "bda58bee1b3cba48cb0d1508c79c23d48413b3dc296aabf5291288783ff037ef";
var PUBLIC_CIPHERTEXT_NP_HEX =
    "51b965fd83d619f9c3fec28330c7564c90439da62ec962f0c22df2e8e5bf9e52" +
    "712755d4bb004a0dcfd8e6e0acc92553805c11158b3e36a3f74d4da6574514e8" +
    "10313bcbe601fe43c7bb74872ab1a252ea78db775175662ed20baf05e870a265" +
    "1a06afdec90e9bd7a21cba0282ae0ca07e82898bcfbcc162d4f6780f5db89216" +
    "7a85bb5d26afc7551f356b054bb1ebb312fa02e212b2d0a751964a6ca790d6dd" +
    "424df1beb5e7887ae8498070955ba65777b02c7e47ebbfdfc81a54b6fa506869" +
    "29cf603b19cbaf1f32ad795ee8b6619b3dd8764626483425334cc892afc9e6e2" +
    "ca371a850ae29336f559da16acc250600febcbd57524ccc0f181c995ce3f74ba";
var PLAINTEXT_SHA256 =
    "44d7b7069244377863405b7c6a8c1e0fde6c68f02631668e41de3e9503429dcb";
var PLAINTEXT_SHA256_SIGNATURE =
    "98349f92a91a2de46a897901a54b395a85fb618ac904d3d01d3c37d54fbdaba5" +
    "f2f17fbcd45b9237b0b2f63398d5ab113c67cf3a356d30a14eeff9b53b0e7bef" +
    "8b347d835cb60550b082d86293f5fb3354a1d6d85ff19f1c6696683dc3ff55d6" +
    "72b88f3d365b0d56a65e3f974a795feee84b2097646673ccb4336950c04a3ba9" +
    "bd189c9ae03ee824bd5a70a5c40c6ea0b124f4256a18a054d175e339c0f4fdfd" +
    "32edacdec17940343889b2f940edf10c9da338db59972735049eea77632ff895" +
    "53d42ded904959718c9cf5e43a50a315ab860be64d0bd4ef69bd01154d2108a9" +
    "5127b0de26318d8b0c87eace03502c0cbfbe4683c5da7cf30bce3a386534b302";

var SSH_PUBLIC_KEY = 
    new Buffer(SSH_PUBLIC_KEY_FILE.toString(UTF8).slice(8), BASE64);
var SSH_PUBLIC_KEY_FINGERPRINT_HEX = "e7738e886aaf6f0301d62d459a892dc3";

var FAKE_SHA256_TO_SIGN =
    "0123456789abcdef00112233445566778899aabbccddeeff9876543210fedcba";
var FAKE_SHA256_SIGNATURE =
    "023fad1e5a94d417fc81ef477cc307578451791a87458794f993b9c8acd680aa" +
    "0458532349fafec4df9351f6962b656b6c71fe977ec9d9c4cc2956a0d22ab9c8" +
    "3a3639148d0bfe2a1d606868bee0b5a0c0d7b2bfaf80d4ed35d31f22733812dd" +
    "454e8beb119c935f250000f44eeefd61d45bffb3aa42bcb8be6eb5331dc83a14" +
    "bfc4df1dd2120f1d1b8539bd28cd4ebb6f3cf9439279278f5d472b75bff73c1b" +
    "9b7cf713f311e3e25d7b0bfa0ee25f25f78c06335d8440e6a96318d0246c1581" +
    "31c351b661694cfd688cd12f16db60ca496ca75338830d98dd1545ca835832d0" +
    "15398a8dbc55eccb5c95fc9e825960ebd99b9b614e18fe0284a2def94cfe9aba";

var PRIVATE_KEY_COMPONENTS = {
   modulus: new Buffer('4Vc173072M53tIJA/RR5U2IbLgesAVCGUTU2WmouBKSs5XmW64av0ezOAzAOFG4oriOvHzGoHBWIFIH7KQ290AWFUkQ6RdDpsRpuMMNCzo7Bx/9GUC57Bb2xzUHICYmJCx0BUYvQEcHrmTQkZ8N3zGNRoXzubKuye0swAGykN78=', 'base64'),
   exponent: new Buffer('AQAB', 'base64'),
   p: new Buffer('9jJD7kB+j+YcBbMtJq+M3wN/l9C9N9o8o2o2pIDPWZ9l5z3mC/0fwsdIdaAZHtwj6yjWkYUQqwcFMzFMd4JJuw==', 'base64'),
   q: new Buffer('6lBXfCfsiPWzLe6klV+vFaDl40x53AMy+pL0VE/f8GSqHwGPL1q1aa2AtiSCD505g6vq934V3K/KDK2THug3zQ==', 'base64'),
   dp: new Buffer('HnGIxOVkwRaLUIkfhDEhElK0bGl7fHSYGvz/VMg427RCPZ4B3Gmoi8VoyGLLuG0wY9vg7I2vyfZMRlBKTFzoEQ==', 'base64'),
   dq: new Buffer('Ieh2gJUWect0npUGZEdwguTB397VU61y1yglC35zncozhEEpg2TRE/XzxmgKGlBaXl+mpSIt773Qs3z66WIZkQ==', 'base64'),
   inverseQ: new Buffer('3inB7CsdrAdr3Isflf3OiYvzKTuRuhGC6TYFpk0P4o8Q1ucyjACWKC1gnvDYqqkdkwkfAg6Dxh3ZP1s9koxbvw==', 'base64'),
   d: new Buffer('OPTnMBpyZxGA1kJaFN348KeKgS71PfvRh3Mwwte1u/y3quT5zZxkkmYNiGa8GFPjumhQmkzd1gNnOu/DwRO1Fwbp0bfqwCLnd2Lz400ZrwN/S+hlzu+YR1rKOH7C7q/BeAm/hGVejsmkl16WgEpkqTzo11566Gat9UWDAw7C1Zk=', 'base64'),
};

// From ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip

var PSS_MODULUS_HEX = 
    "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e"+
    "577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe88"+
    "8b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de775"+
    "1222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5";

var PSS_M_HEX =
    "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e64"+
    "78ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c027"+
    "12e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74"+
    "ff77a53cb729802f6ed4a5ffa8ba159890fc";

var PSS_MHASH_HEX =
    "37b66ae0445843353d47ecb0b4fd14c110e62d6a";

var PSS_EM_HEX =
    "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af" +
    "5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1" +
    "e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a" +
    "75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc";

var PSS_S_HEX =
    "8daa627d3de7595d63056c7ec659e54406f10610128baae821c8b2a0f3936d54" +
    "dc3bdce46689f6b7951bb18e840542769718d5715d210d85efbb596192032c42" +
    "be4c29972c856275eb6d5a45f05f51876fc6743deddd28caec9bb30ea99e02c3" +
    "488269604fe497f74ccd7c7fca1671897123cbd30def5d54a2b5536ad90a747e";

var PSS_PUBLIC_KEY = fs.readFileSync(__dirname + "/pss_tv.pub");

/*
 * Exported bindings
 */

module.exports = {
    BASE64: BASE64,
    BINARY: BINARY,
    HEX:    HEX,
    SHA1:   SHA1,
    SHA256: SHA256,
    UTF8:   UTF8,
    DES_EDE3_CBC: DES_EDE3_CBC,
    
    EXPONENT_HEX:               EXPONENT_HEX,
    FAKE_SHA256_TO_SIGN:        FAKE_SHA256_TO_SIGN,
    FAKE_SHA256_SIGNATURE:      FAKE_SHA256_SIGNATURE,
    MODULUS_HEX:                MODULUS_HEX,
    PASSWORD:                   PASSWORD,
    PASS_PRIVATE_KEY:           PASS_PRIVATE_KEY,
    PLAINTEXT:                  PLAINTEXT,
    PLAINTEXT_PADDED:           PLAINTEXT_PADDED,
    PLAINTEXT_SHA256:           PLAINTEXT_SHA256,
    PLAINTEXT_SHA256_SIGNATURE: PLAINTEXT_SHA256_SIGNATURE,
    PRIVATE_CIPHERTEXT_HEX:     PRIVATE_CIPHERTEXT_HEX,
    PRIVATE_OLD_PAD_CIPHER_HEX: PRIVATE_OLD_PAD_CIPHER_HEX,
    PRIVATE_KEY:                PRIVATE_KEY,
    PRIVATE_KEY_2:              PRIVATE_KEY_2,
    PRIVATE_KEY_3:              PRIVATE_KEY_3,
    PUBLIC_CIPHERTEXT_HEX:      PUBLIC_CIPHERTEXT_HEX,
    PUBLIC_CIPHERTEXT_NP_HEX:   PUBLIC_CIPHERTEXT_NP_HEX,
    PUBLIC_KEY:                 PUBLIC_KEY,
    PUBLIC_KEY_2:               PUBLIC_KEY_2,
    SSH_PUBLIC_KEY:             SSH_PUBLIC_KEY,
    SSH_PUBLIC_KEY_FINGERPRINT_HEX: SSH_PUBLIC_KEY_FINGERPRINT_HEX,
    PRIVATE_KEY_COMPONENTS: PRIVATE_KEY_COMPONENTS,
    PSS_MODULUS_HEX:            PSS_MODULUS_HEX,
    PSS_M_HEX:                  PSS_M_HEX,
    PSS_MHASH_HEX:              PSS_MHASH_HEX,
    PSS_EM_HEX:                 PSS_EM_HEX,
    PSS_S_HEX:                  PSS_S_HEX,
    PSS_PUBLIC_KEY:             PSS_PUBLIC_KEY,

    RsaWrap: ursaNative.RsaWrap,

    ursa:       ursa,
    ursaNative: ursaNative
};
