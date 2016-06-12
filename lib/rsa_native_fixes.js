var OAEP = require('node-rsa/src/schemes/oaep');
var crypt = require('crypto');

function emsa_pss_encode_prehashed(M, emBits) {
    var hash = this.options.signingSchemeOptions.hash || DEFAULT_HASH_FUNCTION;
    var mgf = this.options.signingSchemeOptions.mgf || OAEP.eme_oaep_mgf1;
    var sLen = this.options.signingSchemeOptions.saltLength || DEFAULT_SALT_LENGTH;

    var hLen = OAEP.digestLength[hash];
    var emLen = Math.ceil(emBits / 8);

    if (emLen < hLen + sLen + 2) {
        throw new Error("Output length passed to emBits(" + emBits + ") is too small for the options " +
            "specified(" + hash + ", " + sLen + "). To fix this issue increase the value of emBits. (minimum size: " +
            (8 * hLen + 8 * sLen + 9) + ")"
        );
    }

    var mHash = M;

    var salt = crypt.randomBytes(sLen);

    var Mapostrophe = new Buffer(8 + hLen + sLen);
    Mapostrophe.fill(0, 0, 8);
    mHash.copy(Mapostrophe, 8);
    salt.copy(Mapostrophe, 8 + mHash.length);

    var H = crypt.createHash(hash);
    H.update(Mapostrophe);
    H = H.digest();

    var PS = new Buffer(emLen - salt.length - hLen - 2);
    PS.fill(0);

    var DB = new Buffer(PS.length + 1 + salt.length);
    PS.copy(DB);
    DB[PS.length] = 0x01;
    salt.copy(DB, PS.length + 1);

    var dbMask = mgf(H, DB.length, hash);

    // XOR DB and dbMask together
    var maskedDB = new Buffer(DB.length);
    for (var i = 0; i < dbMask.length; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    var bits = 8 * emLen - emBits;
    var mask = 255 ^ (255 >> 8 - bits << 8 - bits);
    maskedDB[0] = maskedDB[0] & mask;

    var EM = new Buffer(maskedDB.length + H.length + 1);
    maskedDB.copy(EM, 0);
    H.copy(EM, maskedDB.length);
    EM[EM.length - 1] = 0xbc;

    return EM;
};

function emsa_pss_verify_prehashed(M, EM, emBits) {
    var hash = this.options.signingSchemeOptions.hash || DEFAULT_HASH_FUNCTION;
    var mgf = this.options.signingSchemeOptions.mgf || OAEP.eme_oaep_mgf1;
    var sLen = this.options.signingSchemeOptions.saltLength || DEFAULT_SALT_LENGTH;

    var hLen = OAEP.digestLength[hash];
    var emLen = Math.ceil(emBits / 8);

    if (emLen < hLen + sLen + 2 || EM[EM.length - 1] != 0xbc) {
        return false;
    }

    var DB = new Buffer(emLen - hLen - 1);
    EM.copy(DB, 0, 0, emLen - hLen - 1);

    var mask = 0;
    for (var i = 0, bits = 8 * emLen - emBits; i < bits; i++) {
        mask |= 1 << (7 - i);
    }

    if ((DB[0] & mask) !== 0) {
        return false;
    }

    var H = EM.slice(emLen - hLen - 1, emLen - 1);
    var dbMask = mgf(H, DB.length, hash);

    // Unmask DB
    for (i = 0; i < DB.length; i++) {
        DB[i] ^= dbMask[i];
    }

  /*  mask = 0;
    var bits = emBits - 8 * (emLen - 1);
    for (i = 0; i < bits; i++) {
        mask |= 1 << i;
    }
    DB[0] &= mask;*/

    var bits = 8 * emLen - emBits;
    var mask = 255 ^ (255 >> 8 - bits << 8 - bits);
    DB[0] = DB[0] & mask;

    // Filter out padding
    i = 0;
    while (DB[i++] === 0 && i < DB.length);
    if (DB[i - 1] != 1) {
        return false;
    }

    var salt = DB.slice(DB.length - sLen);

    var mHash = M;

    var Mapostrophe = new Buffer(8 + hLen + sLen);
    Mapostrophe.fill(0, 0, 8);
    mHash.copy(Mapostrophe, 8);
    salt.copy(Mapostrophe, 8 + mHash.length);

    var Hapostrophe = crypt.createHash(hash);
    Hapostrophe.update(Mapostrophe);
    Hapostrophe = Hapostrophe.digest();

    return H.toString("hex") === Hapostrophe.toString("hex");
}

module.exports = {
  emsa_pss_encode: emsa_pss_encode_prehashed,
  emsa_pss_verify: emsa_pss_verify_prehashed
};
