function Session() {
  this.id = null;
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

function State(options, child) {
  this.options = options || {};

  // General parameters
  this.type = this.options.type;
  this.version = this.options.version || { major: 1, minor: 1 };
  this.negotiated = false;

  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = this.options.ciphers || [ 'TLS_RSA_WITH_AES_256_CBC_SHA' ];

  this.session = new Session();
  this.pending = new Session();
};
module.exports = State;

State.create = function create(options) {
  return new State(options);
};

State.prototype.switchToPending = function switchToPending() {
  this.session = this.pending;
  this.pending = new Session();

  // TODO(indutny): return false when pending is not initialized
  return true;
};

State.prototype.setRandom = function setRandom(bytes) {
  if (this.type === 'client')
    this.pending.clientRandom = bytes;
  else
    this.pending.serverRandom = bytes;
};

State.prototype.setReceivedRandom = function setReceivedRandom(bytes) {
  if (this.type === 'client')
    this.pending.serverRandom = bytes;
  else
    this.pending.clientRandom = bytes;
};

State.prototype.getCipherSuites = function getCipherSuites() {
  return this.ciphers;
};

State.prototype.selectCipherSuite = function selectCipherSuite(ciphers) {
  // TODO(indutny): intersect support ciphers and given ciphers, and
  // select the most secure
  return ciphers[0];
};
