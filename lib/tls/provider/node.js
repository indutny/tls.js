var assert = require('assert');
var util = require('util');
var stream = require('stream');
var crypto;

function Provider() {
  if (!crypto)
    crypto = require('crypto');
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
  return function() {
    return crypto.createCipher(type);
  };
};

Provider.prototype.decipher = function decipher(type, size) {
  return function() {
    return crypto.createDecipher(type);
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

  this.secret = secret;
  this.label = label;
  this.seed = seed;
  this.pseed = Buffer.concat([ label, seed ], label.length + seed.length);

  // A(i) in RFC5246
  this.a = this.pseed;
}
util.inherits(PRF, stream.Readable);

Provider.prototype.prf = PRF;

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
