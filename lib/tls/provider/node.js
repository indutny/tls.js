var assert = require('assert');
var util = require('util');
var constants = require('constants');
var stream = require('stream');

var asn1 = require('asn1.js');
var rfc3280 = require('asn1.js-rfc3280');
var elliptic;

var utils = require('../../tls.js').utils;
var NullCipher = utils.NullCipher;

var crypto;
var ursa;
var rawCipher;

function Provider() {
  if (!crypto)
    crypto = require('crypto');
  if (process.version < 'v0.11') {
    if (!ursa)
      ursa = require('ursa');
    if (!elliptic)
      elliptic = require('elliptic');
  }
  if (!rawCipher)
    rawCipher = require('raw-cipher');
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

Provider.prototype.mac = function mac(type, size) {
  return function(key) {
    return crypto.createHmac(type, key);
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

Provider.prototype.toVerifyKey = function toVerifyKey(key) {
  return utils.toPEM('RSA PUBLIC KEY', key.data);
};

Provider.prototype.verify = function verify(info) {
  return crypto.createVerify((info.signature + '-' + info.hash).toUpperCase());
};

Provider.prototype.sign = function sign(info) {
  return crypto.createSign((info.signature + '-' + info.hash).toUpperCase());
};

// RSA ops for legacy node
if (process.version < 'v0.11') {
  // Sadly, ursa does not know how to work with RSAPublicKey.
  // We will encode the key in a PublicKey structure to feed it to ursa.
  var PublicKey = asn1.define('PublicKey', function() {
    this.seq().obj(
      this.key('algorithm').use(rfc3280.AlgorithmIdentifier),
      this.key('key').bitstr()
    );
  });

  Provider.prototype.toPrivateKey = function toPrivateKey(key) {
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


// Latest node.js has RSA ops
} else {
  Provider.prototype.toPrivateKey = function toPrivateKey(key) {
    return key;
  };

  Provider.prototype.encryptPublic = function encryptPublic(data, key) {
    var pkey = utils.toPEM('RSA PUBLIC KEY', key.data);
    return crypto.publicEncrypt({
      key: pkey,
      padding: constants.RSA_PKCS1_PADDING
    }, data);
  };

  Provider.prototype.decryptPrivate = function decryptPrivate(data, key) {
    return crypto.privateDecrypt({
      key: key,
      padding: constants.RSA_PKCS1_PADDING
    }, data);
  };

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
