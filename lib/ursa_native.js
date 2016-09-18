var NodeRSA = require('node-rsa');
var BigInteger = require('node-rsa/src/libs/jsbn');
var OAEP = require('node-rsa/src/schemes/oaep');
var nids = require('./nids');
var emsa_pss_encode_prehashed = require('./rsa_native_fixes').emsa_pss_encode;
var emsa_pss_verify_prehashed = require('./rsa_native_fixes').emsa_pss_verify;
var sshKeyDecrypt = require('ssh-key-decrypt');

function textToNid(algorithm) {
  if (typeof nids.byNid[algorithm] !== "undefined")
    return algorithm;
  else if (typeof nids.bySN[algorithm] !== "undefined")
    return nids.bySN[algorithm].nid;
  else if (typeof nids.byLN[algorithm] !== "undefined")
    return nids.byLN[algorithm].nid;
  else
    throw new Error("Unknown algorithm " + algorithm);
}

function RsaWrap() {
  this._key = new NodeRSA();
}

function unimplemented() { throw new Error("NOT IMPLEMENTED"); }

RsaWrap.prototype.generatePrivateKey = function(modulusBits, exponent) {
  if (!this._key.isEmpty())
    throw new Error("Key already set.");
  if (arguments.length < 1)
    throw new Error("Missing args[0].");
  if (typeof arguments[0] !== "number")
    throw new Error("Expected a 32-bit integer in args[0].");
  if (arguments.length < 2)
    throw new Error("Missing args[1].");
  if (typeof arguments[1] !== "number")
    throw new Error("Expected a 32-bit integer in args[1].");
  if (modulusBits < 512)
    throw new Error("Expected modulus bit count >= 512.");
  if (exponent <= 0)
    throw new Error("Expected positive exponent.");
  if ((exponent & 1) === 0)
    throw new Error("Expected odd exponent.");
  this._key.generateKeyPair(modulusBits, exponent);
};

RsaWrap.prototype.getExponent = function() {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  var buf = new Buffer(4);
  buf.writeUInt32BE(this._key.keyPair.e, 0);
  var i = 0;
  while (i < buf.length && buf[i] === 0)
    i++;
  buf = buf.slice(Math.min(3, i));
  return buf;
};

RsaWrap.prototype.getPrivateExponent = function() {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  var buf = this._key.keyPair.d.toBuffer();
  var i = 0;
  while (i < buf.length && buf[i] === 0)
    i++;
  buf = buf.slice(Math.min(3, i));
  return buf;
};

RsaWrap.prototype.getModulus = function() {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  var buf = this._key.keyPair.n.toBuffer();
  var i = 0;
  while (i < buf.length && buf[i] === 0)
    i++;
  buf = buf.slice(Math.min(3, i));
  return buf;
};

RsaWrap.prototype.getPrivateKeyPem = function(passPhrase, cipher) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!this._key.isPrivate())
    throw new Error("Expected a private key.");
  if (arguments.length > 0) {
    var key = sshKeyDecrypt.EVP_BytesToKey(cipher.toUpperCase(), passPhrase, crypto.randomBytes(16));
    crypto.createCipheriv(cipher, key, salt);
    var buf1 = cipher.update(this._key.exportKey('pkcs1-der'));
    return '-----BEGIN RSA PRIVATE KEY-----\n' +
      'Proc-Type: 4,ENCRYPTED\n' +
      'DEK-Info: ' + algorithm.toUpperCase() + ',' + salt.toString('hex').toUpperCase() + '\n' +
      buf1.toString('base64') + '\n'
      '-----END RSA PRIVATE KEY-----\n';
  }
  return new Buffer(this._key.exportKey('pkcs1-pem') + "\n");
};

RsaWrap.prototype.getPublicKeyPem = function() {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  return new Buffer(this._key.exportKey('pkcs8-public-pem') + "\n");
};

// NOTE: This is not re-entrant. It shouldn't be a problem since
// the code is synchronous...

RsaWrap.prototype.privateDecrypt = function(buf, padding) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!this._key.isPrivate())
    throw new Error("Expected a private key.");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[0].");
  if (supported_paddings.indexOf(padding) < 0)
    throw new Error("Expected a 32-bit integer in args[1].");

  if (padding == RSA_NO_PADDING) {
    return this._key.keyPair.$doPrivate(new BigInteger(buf)).toBuffer(this._key.keyPair.encryptedDataLength);
  } else {
    this._key.setOptions({ encryptionScheme: padding });
    return this._key.decrypt(buf);
  }
};

RsaWrap.prototype.privateEncrypt = function(buf, padding) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!this._key.isPrivate())
    throw new Error("Expected a private key.");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[0].");
  if (supported_paddings.indexOf(padding) < 0)
    throw new Error("Expected a 32-bit integer in args[1].");

  if (padding == RSA_NO_PADDING) {
    return this._key.keyPair.$doPrivate(new BigInteger(buf)).toBuffer(this._key.keyPair.encryptedDataLength);
  } else {
    this._key.setOptions({ encryptionScheme: padding });
    return this._key.encryptPrivate(buf);
  }
};

RsaWrap.prototype.publicDecrypt = function(buf, padding) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[0].");
  if (supported_paddings.indexOf(padding) < 0)
    throw new Error("Expected a 32-bit integer in args[1].");

  if (padding == RSA_NO_PADDING) {
    return this._key.keyPair.$doPublic(new BigInteger(buf)).toBuffer(this._key.keyPair.encryptedDataLength);
  } else {
    this._key.setOptions({ encryptionScheme: padding });
    return this._key.decryptPublic(buf);
  }
};

RsaWrap.prototype.publicEncrypt = function(buf, padding) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[0].");
  if (supported_paddings.indexOf(padding) < 0)
    throw new Error("Expected a 32-bit integer in args[1].");

  if (padding == RSA_NO_PADDING) {
    return this._key.keyPair.$doPublic(new BigInteger(buf)).toBuffer(this._key.keyPair.encryptedDataLength);
  } else {
    this._key.setOptions({ encryptionScheme: padding });
    return this._key.encrypt(buf);
  }
};

RsaWrap.prototype.setPrivateKeyPem = function(pem, password) {
  var type = 'pkcs1-pem';
  if (!this._key.isEmpty())
    throw new Error("Key already set.");
  if (arguments.length === 0)
    throw new Error("Missing args[0].");
  if (!Buffer.isBuffer(pem))
    throw new Error("Expected a Buffer in args[0].");
  if (arguments.length > 1 && Buffer.isBuffer(password)) {
    pem = sshKeyDecrypt(pem, password.toString());
    type = 'pkcs1-der';
  }
  else if (arguments.length > 1)
    throw new Error("Expected a Buffer in args[1].");
  else {
    var lines = pem.toString('utf8').split("\n").filter(function(v) { return v != "" });
    if (lines[0] !== '-----BEGIN RSA PRIVATE KEY-----' || lines[lines.length - 1] !== '-----END RSA PRIVATE KEY-----')
      throw new Error("no start line");
  }
  this._key.importKey(pem, type);
};

RsaWrap.prototype.setPublicKeyPem = function(pem) {
  if (arguments.length === 0)
    throw new Error("Missing args[0].");
  if (!Buffer.isBuffer(pem))
    throw new Error("Expected a Buffer in args[0].");
  if (!this._key.isEmpty())
    throw new Error("Key already set.");
  var lines = pem.toString('utf8').split("\n").filter(function(v) { return v != ""; });
  if (lines[0] !== '-----BEGIN PUBLIC KEY-----' || lines[lines.length - 1] !== '-----END PUBLIC KEY-----')
    throw new Error("no start line");
  this._key.importKey(pem, 'pkcs8-public-pem');
};

RsaWrap.prototype.sign = function(algorithm, hash) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (!this._key.isPrivate())
    throw new Error("Expected a private key.");
  if (arguments.length < 1)
    throw new Error("Missing args[0].");
  if (typeof arguments[0] !== "number")
    throw new Error("Expected a 32-bit integer in args[0].");
  if (arguments.length < 2)
    throw new Error("Missing args[1].");
  if (!Buffer.isBuffer(hash))
    throw new Error("Expected a Buffer in args[1].");
  if (!nids.byNid[algorithm])
    throw new Error("unknown algorithm");
  // TODO: Submit a PR to node-rsa so they take care of it themselves.
  this._key.setOptions({ signingScheme: 'pkcs1' });
  var keyPair = this._key.keyPair;
  var paddedHash = keyPair.signingScheme.pkcs1pad(hash, nids.byNid[algorithm].ln);
  return keyPair.$doPrivate(new BigInteger(paddedHash)).toBuffer(keyPair.encryptedDataLength);
};

RsaWrap.prototype.verify = function(algorithm, hash, sig) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (arguments.length < 1)
    throw new Error("Missing args[0].");
  if (typeof arguments[0] !== "number")
    throw new Error("Expected a 32-bit integer in args[0].");
  if (arguments.length < 2)
    throw new Error("Missing args[1].");
  if (!Buffer.isBuffer(hash))
    throw new Error("Expected a Buffer in args[1].");
  if (arguments.length < 3)
    throw new Error("Missing args[2].");
  if (!Buffer.isBuffer(sig))
    throw new Error("Expected a Buffer in args[2].");
  if (!nids.byNid[algorithm])
    throw new Error("unknown algorithm");
  this._key.setOptions({ signingScheme: 'pkcs1' });
  var keyPair = this._key.keyPair;
  var paddedHash = keyPair.signingScheme.pkcs1pad(hash, nids.byNid[algorithm].ln);
  var m = keyPair.$doPublic(new BigInteger(sig));
  return m.toBuffer().toString('hex') == paddedHash.toString('hex');
};

RsaWrap.prototype.createPrivateKeyFromComponents = function(modulus, exponent, p, q, dp, dq, inverseQ, d) {
  this._key.importKey({
    n: modulus,
    e: exponent,
    d: d,
    p: p,
    q: q,
    dmp1: dp,
    dmq1: dq,
    coeff: inverseQ
  }, 'components');
};
RsaWrap.prototype.createPublicKeyFromComponents = function(modulus, exponent) {
  this._key.importKey({
    n: modulus,
    e: exponent
  }, 'components-public');
};

RsaWrap.prototype.openPublicSshKey = function(modulus, exponent) {
  this._key.importKey({
    n: modulus,
    e: exponent
  }, 'components-public');
};

RsaWrap.prototype.addPSSPadding = function(algorithm, buf, salt_len) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (arguments.length < 3)
    throw new Error("Not enough args.");
  if (typeof arguments[0] !== "number")
    throw new Error("Expected a 32-bit integer in args[0].");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[1].");
  if (typeof arguments[2] !== "number")
    throw new Error("Expected a 32-bit integer in args[2].");
  if (!nids.byNid[algorithm])
    throw new Error("unknown algorithm");
  if (salt_len === -1)
    salt_len = OAEP.digestLength[nids.byNid[algorithm].ln];
  else if (salt_len === -2)
    salt_len = Math.ceil((this._key.keyPair.keySize - 1) / 8) - OAEP.digestLength[nids.byNid[algorithm].ln] - 2;
  this._key.setOptions({ signingScheme: { scheme: 'pss', hash: nids.byNid[algorithm].ln, saltLength: salt_len } });
  return emsa_pss_encode_prehashed.call(this._key.keyPair.signingScheme, buf, this._key.keyPair.keySize - 1);
};

RsaWrap.prototype.verifyPSSPadding = function(algorithm, buf, sig, salt_len) {
  if (this._key.isEmpty())
    throw new Error("Key not yet set.");
  if (arguments.length < 4)
    throw new Error("Not enough args.");
  if (typeof arguments[0] !== "number")
    throw new Error("Expected a 32-bit integer in args[0].");
  if (!Buffer.isBuffer(buf))
    throw new Error("Expected a Buffer in args[1].");
  if (!Buffer.isBuffer(sig))
    throw new Error("Expected a Buffer in args[2].");
  if (typeof arguments[3] !== "number")
    throw new Error("Expected a 32-bit integer in args[3].");
  if (!nids.byNid[algorithm])
    throw new Error("unknown algorithm");
  if (salt_len === -1)
    salt_len = OAEP.digestLength[nids.byNid[algorithm].ln];
  else if (salt_len === -2)
    salt_len = Math.ceil((this._key.keyPair.keySize - 1) / 8) - OAEP.digestLength[nids.byNid[algorithm].ln] - 2;
  this._key.setOptions({ signingScheme: { scheme: 'pss', hash: nids.byNid[algorithm].ln, saltLength: salt_len } });
  return emsa_pss_verify_prehashed.call(this._key.keyPair.signingScheme, buf, sig, this._key.keyPair.keySize - 1);
};

const RSA_NO_PADDING = "null";
const RSA_PKCS1_PADDING = "pkcs1";
const RSA_PKCS1_OAEP_PADDING = "pkcs1_oaep";
const RSA_PKCS1_SALT_LEN_HLEN = -1;
const RSA_PKCS1_SALT_LEN_MAX = -2;
const RSA_PKCS1_SALT_LEN_RECOVER = -2;

var supported_paddings = [ RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING ];

module.exports = {
  RsaWrap: RsaWrap,
  textToNid: textToNid,
  RSA_NO_PADDING: RSA_NO_PADDING,
  RSA_PKCS1_PADDING: RSA_PKCS1_PADDING,
  RSA_PKCS1_OAEP_PADDING: RSA_PKCS1_OAEP_PADDING,
  RSA_PKCS1_SALT_LEN_HLEN: RSA_PKCS1_SALT_LEN_HLEN,
  RSA_PKCS1_SALT_LEN_MAX: RSA_PKCS1_SALT_LEN_MAX,
  RSA_PKCS1_SALT_LEN_RECOVER: RSA_PKCS1_SALT_LEN_RECOVER
};
