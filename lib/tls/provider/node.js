var assert = require('assert');
var constants = require('constants');

var elliptic;

var utils = require('../../tls.js').utils;
var NullCipher = utils.NullCipher;

var crypto;
var rawCipher;
var rawRSA;
var md5sha1;
var prf;

function Provider() {
  if (!crypto)
    crypto = require('crypto');
  if (process.version < 'v0.11') {
    if (!elliptic)
      elliptic = require('elliptic');
  }
  if (!rawCipher)
    rawCipher = require('raw-cipher');
  if (!rawRSA)
    rawRSA = require('raw-rsa');
  if (!md5sha1)
    md5sha1 = require('md5-sha1');
  if (!prf)
    prf = require('prf');
}
module.exports = Provider;

Provider.create = function create() {
  return new Provider();
};

Provider.prototype.random = function random(size) {
  return crypto.randomBytes(size);
};

Provider.prototype.hash = function hash(type, size) {
  return function() {
    return crypto.createHash(type);
  };
};

Provider.prototype.mac = function mac(type) {
  return function(key) {
    return crypto.createHmac(type, key);
  };
};

function SSL3Hash() {
  this._handle = new md5sha1.Digest();
}

SSL3Hash.prototype.update = function update(buf) {
  this._handle.update(buf);
  return this;
};

SSL3Hash.prototype.digest = function digest() {
  var out = new Buffer(36);
  this._handle.digest(out);
  return out;
};

Provider.prototype.ssl3hash = function ssl3hash() {
  return function() {
    return new SSL3Hash();
  };
};

var zbuf = new Buffer(0);

Provider.prototype.cipher = function cipher(info) {
  if (info.name === 'null') {
    return function() {
      return new NullCipher();
    };
  }
  return function(pass, iv) {
    return rawCipher.createCipher(info.name, pass || zbuf, iv || zbuf);
  };
};

Provider.prototype.decipher = function decipher(info) {
  if (info.name === 'null') {
    return function() {
      return new NullCipher();
    };
  }
  return function(pass, iv) {
    return rawCipher.createDecipher(info.name, pass || zbuf, iv || zbuf);
  };
};

Provider.prototype.toVerifyKey = function toVerifyKey(key) {
  return utils.toPEM('RSA PUBLIC KEY', key);
};

function MD5SHA1(crypto) {
  this.md5 = crypto.hash('md5')();
  this.sha1 = crypto.hash('sha1')();
}

MD5SHA1.prototype.update = function update(buf, enc) {
  this.md5.update(buf, enc);
  this.sha1.update(buf, enc);

  return this;
};

MD5SHA1.prototype.sign = function sign(key) {
  var h = Buffer.concat([ this.md5.digest(), this.sha1.digest() ]);
  return md5sha1.sign(h, key);
};

MD5SHA1.prototype.verify = function verify(key, content) {
  if (!(key instanceof Buffer))
    key = new Buffer(key);

  var h = Buffer.concat([ this.md5.digest(), this.sha1.digest() ]);
  return md5sha1.verify(h, content, key);
};

Provider.prototype.verify = function verify(info) {
  if (info.hash === 'md5-sha1')
    return new MD5SHA1(this);

  return crypto.createVerify((info.signature + '-' + info.hash).toUpperCase());
};

Provider.prototype.sign = function sign(info) {
  if (info.hash === 'md5-sha1')
    return new MD5SHA1(this);

  return crypto.createSign((info.signature + '-' + info.hash).toUpperCase());
};

function PRF(digest, secret, label, seeds) {
  this.digest = digest;
  this.secret = secret;
  this.label = label;
  this.seeds = seeds;
  this.finished = false;
}

PRF.prototype.read = function read(size) {
  if (this.finished)
    throw new Error('PRF used twice');

  var out = new Buffer(size);
  if (this.seeds.length === 1)
    prf.generate(out, this.digest, this.secret, this.label, this.seeds[0]);
  else if (this.seeds.length === 2)
    prf.generate(out, this.digest, this.secret, this.label, this.seeds[0], this.seeds[1]);
  else
    throw new Error('Invalid seed count');

  return out;
};

Provider.prototype.prf = function prf(digest) {
  return function(secret, label, seeds) {
    return new PRF(digest, secret, label, seeds);
  };
};

Provider.prototype.toPrivateKey = function toPrivateKey(key) {
  return new rawRSA.Key(key);
};

Provider.prototype.toPublicKey = function toPublicKey(key) {
  return new rawRSA.Key(key);
};

Provider.prototype.encryptPublic = function encryptPublic(out, data, key) {
  var r = key.publicEncrypt(out, data, rawRSA.RSA_PKCS1_PADDING);
  if (r.length === out.length)
    return out;
  else
    return out.slice(0, r);
};

Provider.prototype.decryptPrivate = function decryptPrivate(out, data, key) {
  var r = key.privateDecrypt(out, data, rawRSA.RSA_PKCS1_PADDING);
  if (r.length === out.length)
    return out;
  else
    return out.slice(0, r);
};

if (process.version < 'v0.11') {
  Provider.prototype.getECC = function getECC(params) {
    // TODO(indutny): support other curves too
    assert.equal(params.type, 'named_curve');

    var curve = null;
    var match = params.value.match(/^secp(\d+)r1$/i);
    if (match)
      return new elliptic.ec('p' + match[1]);

    return new elliptic.ec(params.value);
  };

  Provider.prototype.genECDHEPair = function genECDHEPair(params) {
    return this.getECC(params).genKeyPair();
  };

  Provider.prototype.toECDHEPub = function toECDHEPub(params, point) {
    return this.getECC(params).keyPair(null, point).getPublic();
  };

  Provider.prototype.deriveECDHE = function deriveECDHE(priv, pub) {
    return new Buffer(priv.derive(pub).toArray());
  };

  Provider.prototype.getECDHEPub = function getECDHEPub(priv) {
    return new Buffer(priv.getPublic('array'));
  };


} else {
  Provider.prototype.getECC = function getECC(params) {
    // TODO(indutny): support other curves too
    assert.equal(params.type, 'named_curve');

    var match = params.value.match(/^secp(\d+)r1$/i);
    if (match)
      return crypto.createECDH('prime' + match[1] + 'v1');

    return crypto.createECDH(params.value);
  };

  Provider.prototype.genECDHEPair = function genECDHEPair(params) {
    var ecdhe = this.getECC(params);
    ecdhe.generateKeys();
    return ecdhe;
  };

  Provider.prototype.toECDHEPub = function toECDHEPub(params, point) {
    return point;
  };

  Provider.prototype.deriveECDHE = function deriveECDHE(priv, pub) {
    return priv.computeSecret(pub);
  };

  Provider.prototype.getECDHEPub = function getECDHEPub(priv) {
    return priv.getPublicKey();
  };

}
