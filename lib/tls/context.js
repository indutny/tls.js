var utils = require('../tls').utils;

function Context(options) {
  this.options = options || {};

  this.crypto = options.provider;
  this.keys = {};
  this.ciphers = null;
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
    key: this.crypto.privateKey(pair.key),
    certs: certs
  };
};

Context.prototype.setCiphers = function setCiphers(ciphers) {
  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = ciphers;
};
