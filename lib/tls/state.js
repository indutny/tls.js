var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var rfc3280 = require('asn1.js-rfc3280');

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
  this.preMaster = null;
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

function State(options) {
  EventEmitter.call(this);

  this.options = options || {};

  this.context = this.options.context;
  if (!this.context)
    throw new Error('Context is a required option when creating a socket');

  // Just a shortcut
  this.crypto = this.context.crypto;
  this.socket = this.options.socket;
  this.framer = this.options.framer;
  this.parser = this.options.parser;

  // General parameters
  this.type = this.options.type;
  this.version = this.options.version || { major: 3, minor: 3 };
  this.secure = false;

  // TODO(indutny) support OpenSSL-like cipher list
  this.ciphers = this.options.ciphers || [ 'TLS_RSA_WITH_AES_256_CBC_SHA' ];
  this.key = null;

  // State machine data
  this.wait = 'hello';
  this.initialWait = this.wait;
  this.skip = {};

  this.writeSession = new Session();
  this.readSession = new Session();
  this.pending = new Session();

  var self = this;
  this.framer.on('random', function(bytes) {
    self.setRandom(bytes);
  });
};
util.inherits(State, EventEmitter);
module.exports = State;

State.create = function create(options) {
  return new State(options);
};

State.prototype.handle = function handle(frame) {
  // Alert level protocol
  do {
    var handled = false;

    if (frame.type === 'alert')
      handled = this.handleAlert(frame);
    else if (frame.type === 'handshake')
      handled = this.handleHandshake(frame);
    else if (frame.type === 'change_cipher_spec')
      handled = this.handleChangeCipher(frame);
  } while (handled === this.skip);

  return handled;
};

State.prototype.handleAlert = function handleAlert(frame) {
  if (frame.level === 'fatal') {
    this.socket.destroySoon();
    this.emit('error', new Error('Received alert: ' + frame.description));
    return true;
  }

  // TODO(indutny): Handle not fatal alerts
  return true;
};

State.prototype.handleHandshake = function handleHandshake(frame) {
  // NOTE: We are doing it not in parser, because parser may parse more
  // frames that we have yet observed.
  // Accumulate state for `verifyData` hash
  // TODO(indutny) renegotiation
  if (!this.secure)
    this.addHandshakeMessage(frame.buffers);

  if (this.type === 'client')
    return this.clientHandleHandshake();
  else
    return this.serverHandleHandshake();
};

//
// Client methods
//

State.prototype.clientHandleHandshake = function clientHandleHandshake(frame) {
  var htype = frame.handshakeType;

  if (this.wait === 'hello') {
    if (htype !== 'server_hello')
      return false;

    if (!this.clientHandleHello(frame))
      return false;
  } else if (this.wait === 'certificate' || this.wait === 'optCertificate') {
    if (htype !== 'certificate') {
      if (this.wait === 'certificate')
        return false;

      this.wait = 'keyExchange';
      return this.skip;
    }

    if (!this.clientHandleCert(frame))
      return false;

    // TODO(indunty): support DHE
    this.wait = 'certReq';
  } else if (this.wait === 'keyExchange') {
    if (htype !== 'server_key_exchange')
      return false;

    this.wait = 'certReq';
  } else if (this.wait === 'certReq') {
    if (htype !== 'certificate_request') {
      this.wait = 'helloDone';
      return this.skip;
    }

    this.wait = 'helloDone';
  } else if (this.wait === 'helloDone') {
    if (htype !== 'server_hello_done')
      return false;

    // Send verify data and clear messages
    this.clientHandleHelloDone(frame);

    this.wait = 'finished';
  } else if (this.wait === 'finished'){
    if (htype !== 'finished' || !this.bothSwitched())
      return false;

    // TODO(indutny): renegotiation?
    this.wait = 'none';
    this.secure = true;
    this.emit('secure');
  } else {
    return false;
  }
  return true;
};

State.prototype.clientHandleHello = function clientHandleHello(frame) {
  this.setReceivedRandom(frame.random.bytes);
  this.selectCipherSuite([ frame.cipherSuite ]);

  // TODO(indutny): support anonymous ciphers
  this.wait = 'certificate';

  return true;
};

State.prototype.clientHandleCert = function clientHandleCert(frame) {
  try {
    var certs = frame.certs.map(function(cert) {
      return rfc3280.Certificate.decode(cert, 'der');
    });
  } catch (e) {
    this._error('bad_certificate', e);
    return false;
  }

  var leaf = this.crypto.getLeaf(certs);
  if (!leaf) {
    this._error('certificate_unknown', 'No leaf certificate available');
    return false;
  }
  this.key = { key: null, certs: frame.certs, leaf: leaf };
  this.emit('cert', leaf, frame.certs);

  return true;
};

State.prototype.clientHandleHelloDone = function clientHandleHelloDone(frame) {
  // TODO(indutny): Anonymous ciphers
  // TODO(indutny): Certificate requests
  if (this.key === null)
    return false;

  // TODO(indunty): async may be?

  // TODO(indutny): Support non-RSA ciphers
  var size = 46 + 2;
  this.preMaster = new Buffer(2 + size);
  this.preMaster.writeUInt16BE(size, 0);
  this.preMaster[2] = this.version.major;
  this.preMaster[3] = this.version.minor;
  this.crypto.random(46).copy(this.preMaster, 4);

  // TODO(indutny): Check algorithm
  var pub = this.key.leaf.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
  var content = this.crypto.encryptPublic(this.preMaster, pub);
  this.framer.keyExchange('client', content);

  this.changeCipherAndFinish();
};

//
// Server methods
//

State.prototype.serverHandleHandshake = function serverHandleHandshake(frame) {
  var htype = frame.handshakeType;

  if (this.wait === 'hello') {
    if (htype !== 'client_hello')
      return false;

    if (this.serverHandleHello(frame))
      return false;

    this.wait = 'keyExchange';
  } else if (this.wait === 'certificate') {
    if (htype !== 'certificate') {
      this.wait = 'keyExchange';
      return this.skip;
    }

    this.wait = 'keyExchange';
  } else if (this.wait === 'keyExchange') {
    if (htype !== 'client_key_exchange')
      return false;

    if (this.serverHandleKeyEx(frame))
      return false;

    this.wait = 'certVerify';
  } else if (this.wait === 'certVerify') {
    if (htype !== 'certificate_verify') {
      this.wait = 'finished';
      return this.skip;
    }

    this.wait = 'finished';
  } else if (this.wait === 'finished') {
    if (htype !== 'finished' || !this.bothSwitched())
      return false;

    // TODO(indutny): renegotiation?
    this.wait = 'none';
    this.secure = true;
    this.emit('secure');
  } else {
    return false;
  }

  return true;
};

State.prototype.serverHandleHello = function serverHandleHello(frame) {
  this.setReceivedRandom(frame.random.bytes);
  this.framer.hello('server', {
    cipherSuite: this.selectCipherSuite(frame.cipherSuites)
  });
  if (this.key !== null)
    this.framer.certificate(this.key.certs);

  // TODO(indutny): Server key exchange for DHE, CertificateRequest

  this.framer.helloDone();

  return true;
};

State.prototype.serverHandleKeyEx = function serverHandleKeyEx(frame) {
  if (this.key === null)
    return false;

  // TODO(indutny): Support DHE
  frame.content;

  return true;
};

//
// Common parts
//

State.prototype.handleChangeCipher = function handleChangeCipher() {
  // Parser already handles it
};

//
// Routines
//

State.prototype._error = function error(description, msg) {
  this.framer.alert('fatal', description);
  this.socket.destroySoon();
  this.emit('error', msg instanceof Error ? msg : new Error(msg));
};

State.prototype.changeCipherAndFinish = function changeCipherAndFinish() {
  // Send verify data and clear messages
  this.framer.changeCipherSpec();

  // All consecutive writes will be encrypted
  this.switchToPending('write');

  var verifyData = this.getVerifyData();
  if (verifyData)
    this.framer.finished(verifyData);
  else
    this._error('unexpected_message', 'Session is not initialized');
};

State.prototype.decrypt = function decrypt(body, cb) {
  if (this.readSession.cipher === null)
    return cb(body);
  else
    throw new Error('Decryption not implemented yet');
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

  // TODO(indutny) use keypair depending on cipher, SNI
  this.key = this.context.keys.rsa;
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

// Dummy state
function Dummy() {
  this.encrypted = false;

  this.version = {
    major: 3,
    minor: 3
  };
}

Dummy.prototype.switchToPending = function switchToPending() {
  this.encrypted = true;
};

Dummy.prototype.decrypt = function decrypt(body, cb) {
  if (this.encrypted)
    return null;
  else
    return cb(body);
};

Dummy.prototype.addHandshakeMessage = function addHandshakeMessage() {
};

State.createDummy = function createDummy() {
  return new Dummy();
};
