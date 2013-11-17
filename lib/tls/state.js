function State(options) {
  this.options = options || {};

  // General parameters
  this.type = this.options.type;
  this.version = this.options.version || { major: 1, minor: 1 };
  this.negotiating = true;

  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = this.options.ciphers || [ 'TLS_RSA_WITH_AES_256_CBC_SHA' ];

  // TLS parameters
  this.prf = null;
  this.cipher = null;
  this.cipherType = null;
  this.keyLength = 0;
  this.blockLength = 0;
  this.fixedIVLength = 0;
  this.recordIVLength = 0;
  this.mac = null;
  this.macLength = 0;
  this.macKeyLength = 0;
  this.compression = null;
  this.masterSecret = null;
  this.clientRandom = null;
  this.serverRandom = null;
};
module.exports = State;

State.create = function create(options) {
  return new State(options);
};

State.prototype.clone = function clone() {
  return State.create(this.options);
};

State.prototype.setRandom = function setRandom(bytes) {
  if (this.type === 'client')
    this.clientRandom = bytes;
  else
    this.serverRandom = bytes;
};

State.prototype.setReceivedRandom = function setReceivedRandom(bytes) {
  if (this.type === 'client')
    this.serverRandom = bytes;
  else
    this.clientRandom = bytes;
};

State.prototype.getCipherSuites = function getCipherSuites() {
  return this.ciphers;
};
