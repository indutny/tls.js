function Context(options) {
  this.options = options || {};

  this.cert = options.cert;
  this.crypto = options.provider;
};
module.exports = Context;

Context.create = function create(options) {
  return new Context(options);
};
