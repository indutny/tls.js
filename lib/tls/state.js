var assert = require('assert');
var tls = require('../tls');

function Session() {
  this.id = null;

  this.info = null;
  this.prf = null;
  this.cipher = null;
  this.keyLength = 0;
  this.fixedIVLength = 0;
  this.recordIVLength = 0;
  this.mac = null;
  this.compression = null;
  this.masterSecret = null;
  this.clientRandom = null;
  this.serverRandom = null;

  // All messages in this handshake
  this.recording = false;
  this.handshakeMessages = [];
};

Session.prototype.load = function load(crypto, cipher) {
  var info = tls.constants.cipherInfoByName[cipher];

  this.info = info;
  this.prf = crypto.prf;
  this.cipher = crypto.cipher(info.bulk, info.bulkSize);
  this.decipher = crypto.decipher(info.bulk, info.bulkSize);
  this.keyLength = crypto.cipherKeyLength(info.bulk, info.bulkSize);
  this.mac = crypto.mac(info.mac, info.macSize);
};

function State(options, child) {
  this.options = options || {};

  this.context = this.options.context;
  if (!this.context)
    throw new Error('Context is a required option when creating a socket');

  // Just a shortcut
  this.crypto = this.context.crypto;

  // General parameters
  this.type = this.options.type;
  this.version = this.options.version || { major: 3, minor: 3 };
  this.negotiated = false;

  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = this.options.ciphers || [ 'TLS_RSA_WITH_AES_256_CBC_SHA' ];

  this.writeSession = new Session();
  this.readSession = new Session();
  this.pending = new Session();
};
module.exports = State;

State.create = function create(options) {
  return new State(options);
};

State.prototype.switchToPending = function switchToPending(side) {
  if (side === 'read')
    this.readSession = this.pending;
  else
    this.writeSession = this.pending;

  // Reset state
  if (this.readSession === this.pending && this.writeSession === this.pending) {
    this.pending.clearMessages();
    this.pending = new Session();
  }

  // TODO(indutny): return false when pending is not initialized
  return true;
};

State.prototype.bothSwitched = function bothSwitched() {
  return this.readSession === this.writeSession;
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
  var cipher = ciphers[0];
  this.pending.load(this.crypto, cipher);
  return cipher;
};

State.prototype.getVerifyData = function getVerifyData(side) {
  var session = side === 'read' ? this.readSession : this.writeSession;

  // Not initialized
  if (session.prf === null ||
      session.mac === null ||
      session.masterSecret === null) {
    return null;
  }

  return new session.prf(session.masterSecret,
                         this.type + ' finished',
                         this.hashMessages(session))
                    .read(session.info.verifyLength);
};

State.prototype.recordMessages = function recordMessages() {
  this.pending.recording = true;
};

State.prototype.clearMessages = function clearMessages() {
  this.pending.recording = false;
  this.pending.handshakeMessages = [];
  assert(this.write === this.pending);
};

State.prototype.hashMessages = function hashMessages(session) {
  var hash = session.mac();
  for (var i = 0; i < session.handshakeMessages.length; i++)
    hash.update(session.handshakeMessages[i]);
  return hash.digest('buffer');
};

State.prototype.computeMaster = function computeMaster() {
  var session = this.pending;

  session.masterSecret = new session.prf(
    session.preMaster,
    'master secret',
    Buffer.concat([ session.clientRandom, session.serverRandom ])
  ).read(tls.constants.masterLength);

  return session.masterSecret;
};

State.prototype.addHandshakeMessage = function addHandshakeMessage(buffers) {
  // TODO(indutny): Write into hashing function, once it will be available
  if (this.pending.recording)
    for (var i = 0; i < buffers.length; i++)
      this.pending.handshakeMessages.push(buffers[i]);
};
