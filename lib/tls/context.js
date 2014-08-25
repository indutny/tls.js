function Context(options) {
  this.options = options || {};

  this.keys = {};
  this.crypto = options.provider;
};
module.exports = Context;

Context.create = function create(options) {
  return new Context(options);
};

Context.prototype.addKeyPair = function addKeyPair(name, pair) {
  this.keys[name] = {
    key: pair.key,
    certs: Array.isArray(pair.cert) ? pair.cert : [ pair.cert ]
  };
};
