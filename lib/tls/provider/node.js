var assert = require('assert');
var util = require('util');
var stream = require('stream');
var asn1 = require('asn1.js');
var rfc3280 = require('asn1.js-rfc3280');

var utils = require('../../tls.js').utils;

var crypto;
var ursa;

function Provider() {
  if (!crypto)
    crypto = require('crypto');
  if (!ursa)
    ursa = require('ursa');
}
module.exports = Provider;

Provider.create = function create() {
  return new Provider();
};

Provider.prototype.random = function random(size) {
  return crypto.randomBytes(size);
};

Provider.prototype.mac = function mac(type, size) {
  return function() {
    return crypto.createHash(type);
  };
};

Provider.prototype.cipher = function cipher(type, size) {
  return function(pass) {
    return crypto.createCipher(type, pass);
  };
};

Provider.prototype.decipher = function decipher(type, size) {
  return function(pass) {
    return crypto.createDecipher(type, pass);
  };
};

Provider.prototype.cipherKeyLength = function cipherKeyLength(type, size) {
  return size;
};

function PRF(name, secret, label, seed) {
  assert.equal(name, 'sha256');

  // 32 bytes = 256 bits, we should not generate way too much entropy
  stream.Readable.call(this, {
    highWaterMark: 32
  });

  if (typeof label === 'string')
    label = new Buffer(label);

  this.secret = secret;
  this.label = label;
  this.seed = seed;
  this.pseed = Buffer.concat([ label, seed ], label.length + seed.length);

  // A(i) in RFC5246
  this.a = this.pseed;
}
util.inherits(PRF, stream.Readable);

Provider.prototype.prf = function prf(name) {
  return function(secret, label, seed) {
    return new PRF(name, secret, label, seed);
  };
};

PRF.prototype.hmac = function hmac(secret) {
  return crypto.createHmac('sha256', secret);
};

PRF.prototype.getA = function getA() {
  this.a = this.hmac(this.secret).update(this.a).digest('buffer');
  return this.a;
};

PRF.prototype._read = function read(size) {
  var off = 0;
  while (off < size) {
    var c = this.hmac(this.secret).update(this.getA())
                                  .update(this.pseed)
                                  .digest('buffer');
    this.push(c);
    off += c.length;
  }
};

// Sadly, ursa does not know how to work with RSAPublicKey.
// We will encode the key in a PublicKey structure to feed it to ursa.
var PublicKey = asn1.define('PublicKey', function() {
  this.seq().obj(
    this.key('algorithm').use(rfc3280.AlgorithmIdentifier),
    this.key('key').bitstr()
  );
});

Provider.prototype.privateKey = function privateKey(key) {
  return ursa.createPrivateKey(key);
};

Provider.prototype.encryptPublic = function encryptPublic(data, key) {
  var pkey = utils.toPEM('PUBLIC KEY', PublicKey.encode({
    algorithm: {
      algorithm: [ 1, 2, 840, 113549, 1, 1, 1 ]
    },
    key: {
      unused: 0,
      data: key.data || key
    }
  }, 'der'));

  pkey = ursa.createPublicKey(pkey);
  return pkey.encrypt(data, 'binary', undefined, ursa.RSA_PKCS1_PADDING);
};

Provider.prototype.decryptPrivate = function decryptPrivate(data, key) {
  return key.decrypt(data, 'binary', undefined, ursa.RSA_PKCS1_PADDING);
};
