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
