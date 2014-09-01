var utils = require('../tls').utils;

function Context(options) {
  this.options = options || {};

  this.crypto = options.provider;
  this.keys = {};
  this.ciphers = null;
  this.curve = 'secp256r1';

  this.minVersion = null;
  this.maxVersion = null;
};
module.exports = Context;

Context.create = function create(options) {
  return new Context(options);
};

Context.prototype.addKeyPair = function addKeyPair(name, pair) {
  var certs = Array.isArray(pair.cert) ? pair.cert : [ pair.cert ];

  // Decode PEM
  certs = certs.map(function(cert) {
    return utils.fromPEM(cert);
  });

  this.keys[name] = {
    pem: pair.key,
    key: this.crypto.toPrivateKey(pair.key),
    certs: certs
  };
};

Context.prototype.setCiphers = function setCiphers(ciphers) {
  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = ciphers;
};

Context.prototype.setCurve = function setCurve(curve) {
  this.curve = curve;
};

function strToVersion(v) {
  if (/^tls1\.2$/i.test(v))
    return 0x0303;
  else if (/^tls1\.1$/i.test(v))
    return 0x0302;
  else if (/^tls1(\.0)?$/i.test(v))
    return 0x0301;
  else if (/^ssl3?$/i.test(v))
    return 0x0300;
  else
    throw new Error('Unknown version');
}

Context.prototype.setMinVersion = function setMinVersion(v) {
  this.minVersion = strToVersion(v);
};

Context.prototype.setMaxVersion = function setMaxVersion(v) {
  this.maxVersion = strToVersion(v);
};

Context.prototype.setVersion = function setVersion(v) {
  var n = strToVersion(v);
  this.minVersion = n;
  this.maxVersion = n;
};
