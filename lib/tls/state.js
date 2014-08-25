var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var rfc3280 = require('asn1.js-rfc3280');

var tls = require('../tls');
var utils = tls.utils;

function Session(state) {
  this.state = state;
  this.id = null;

  this.info = null;
  this.prf = null;
  this.cipher = null;
  this.decipher = null;
  this.cipherAlg = null;
  this.decipherAlg = null;
  this.keyLength = 0;
  this.macKeyLength = 0;
  this.fixedIVLength = 0;
  this.recordIVLength = 0;
  this.mac = null;
  this.hash = null;
  this.compression = null;
  this.preMaster = null;
  this.masterSecret = null;
  this.clientRandom = null;
  this.serverRandom = null;

  // Keys
  this.clientWriteMacKey = null;
  this.serverWriteMacKey = null;
  this.macReadKey = null;
  this.macWriteKey = null;
  this.clientWriteKey = null;
  this.serverWriteKey = null;
  this.clientWriteIV = null;
  this.serverWriteIV = null;

  // All messages in this handshake
  this.recording = false;
  this.handshakeMessages = [];
};

Session.prototype.computeMaster = function computeMaster() {
  // Already initialized
  if (this.masterSecret !== null)
    return;

  var randoms = Buffer.concat([ this.clientRandom, this.serverRandom ]);

  this.masterSecret = this.prf(this.preMaster, 'master secret', randoms)
      .read(tls.constants.masterLength);

  var keyBlock = this.prf(this.masterSecret, 'key expansion', randoms);

  this.clientWriteMacKey = keyBlock.read(this.macKeyLength / 8);
  this.serverWriteMacKey = keyBlock.read(this.macKeyLength / 8);
  this.clientWriteKey = keyBlock.read(this.keyLength / 8);
  this.serverWriteKey = keyBlock.read(this.keyLength / 8);
  this.clientWriteIV = keyBlock.read(this.fixedIVLength / 8);
  this.serverWriteIV = keyBlock.read(this.fixedIVLength / 8);

  if (this.state.type === 'client') {
    this.cipher = this.cipherAlg(this.clientWriteKey, this.clientWriteIV);
    this.decipher = this.decipherAlg(this.serverWriteKey, this.serverWriteIV);
    this.macWriteKey = this.clientWriteMacKey;
    this.macReadKey = this.serverWriteMacKey;
  } else {
    this.cipher = this.cipherAlg(this.serverWriteKey, this.serverWriteIV);
    this.decipher = this.decipherAlg(this.clientWriteKey, this.clientWriteIV);
    this.macReadKey = this.clientWriteMacKey;
    this.macWriteKey = this.serverWriteMacKey;
  }
};

Session.prototype.load = function load(crypto, cipher) {
  var info = tls.constants.cipherInfoByName[cipher];

  this.info = info;
  this.prf = crypto.prf(info.prf);
  this.cipherAlg = crypto.cipher(info.bulk);
  this.cipher = null;
  this.decipherAlg = crypto.decipher(info.bulk);
  this.decipher = null;
  this.keyLength = info.bulk.keySize;
  this.mac = crypto.mac(info.mac, info.macSize);
  this.hash = crypto.hash(info.mac, info.macSize);
  this.macKeyLength = info.macSize;

  // TODO(indutny) what about rest?
  if (/aes/.test(info.bulk.name))
    this.fixedIVLength = info.bulk.size;

  // TODO(indunty): what about rest?
  if (info.type === 'block')
    this.recordIVLength = info.bulk.size;
  else
    this.recordIVLength = 0;
};

Session.prototype.recordMessages = function recordMessages() {
  this.recording = true;
};

Session.prototype.clearMessages = function clearMessages() {
  this.recording = false;
  this.handshakeMessages = [];
};

Session.prototype.hashMessages = function hashMessages() {
  var hash = this.hash();
  for (var i = 0; i < this.handshakeMessages.length; i++)
    hash.update(this.handshakeMessages[i]);
  return hash.digest('buffer');
};

Session.prototype.addHandshakeMessage = function addHandshakeMessage(buffers) {
  // TODO(indutny): Write into hashing function, once it will be available
  if (!this.recording)
    return;

  for (var i = 0; i < buffers.length; i++)
    this.handshakeMessages.push(buffers[i]);
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
  this.framer = tls.framer.create(this);
  this.parser = tls.parser.create(this);

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

  this.writeSession = new Session(this);
  this.readSession = new Session(this);
  this.pending = new Session(this);

  // Start recording messages
  this.pending.recordMessages();

  var self = this;
  this.framer.on('random', function(bytes) {
    self.setRandom(bytes);
  });

  this.framer.on('handshakeMsg', function(buffers) {
    self.pending.addHandshakeMessage(buffers);
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
    var start = this.wait;
    var handled = false;

    if (frame.type === 'alert')
      handled = this.handleAlert(frame);
    else if (frame.type === 'handshake')
      handled = this.handleHandshake(frame);
    else if (frame.type === 'change_cipher_spec')
      handled = this.handleChangeCipher(frame);

    if (start !== this.wait)
      this.emit('stateChange', start, this.wait);
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
    this.pending.addHandshakeMessage(frame.buffers);

  if (this.type === 'client')
    return this.clientHandleHandshake(frame);
  else
    return this.serverHandleHandshake(frame);
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
  this.setReceivedRandom(frame.random.raw);
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

  var leaf = utils.getLeaf(this.crypto, certs);
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
  var size = 46;
  var preMaster = new Buffer(2 + size);
  preMaster[0] = this.version.major;
  preMaster[1] = this.version.minor;
  this.crypto.random(46).copy(preMaster, 2);

  this.pending.preMaster = preMaster;

  // TODO(indutny): Check algorithm
  var pub = this.key.leaf.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
  var content = this.crypto.encryptPublic(preMaster, pub);

  var prefix = new Buffer(2);
  prefix.writeUInt16BE(content.length, 0, true);
  content = Buffer.concat([ prefix, content ]);
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

    if (!this.serverHandleHello(frame))
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

    if (!this.serverHandleKeyEx(frame))
      return false;

    this.wait = 'certVerify';
  } else if (this.wait === 'certVerify') {
    if (htype !== 'certificate_verify') {
      debugger;
      this.wait = 'finished';
      return this.skip;
    }

    this.wait = 'finished';
  } else if (this.wait === 'finished') {
    // TODO(indutny): renegotiation?
    if (htype !== 'finished' || this.bothSwitched())
      return false;

    this.changeCipherAndFinish();

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
  this.setReceivedRandom(frame.random.raw);
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

  if (frame.content.length < 2)
    return false;
  var len = frame.content.readUInt16BE(0, true);
  if (frame.content.length !== 2 + len)
    return false;

  var content = frame.content.slice(2);

  // TODO(indutny): Support DHE
  try {
    this.pending.preMaster = this.crypto.decryptPrivate(content, this.key.key);
  } catch (e) {
    this._error('decrypt_error', e);
    return false;
  }

  return true;
};

//
// Common parts
//

State.prototype.handleChangeCipher = function handleChangeCipher() {
  // Parser already handles it
  return true;
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
  this.writeSession.clearMessages();
  if (verifyData)
    this.framer.finished(verifyData);
  else
    this._error('unexpected_message', 'Session is not initialized');
};

State.prototype.decrypt = function decrypt(body) {
  if (this.readSession.decipher === null)
    return null;

  var session = this.readSession;


  if (session.info.bulk.cbc) {
    var iv = body.slice(0, session.recordIVLength / 8);
    var c = body.slice(iv.length);
    var out = new Buffer(c.length);
    session.decipher.write(out, c);

    return out;
  } else {
    throw new Error('Unsupported cipher type');
  }
};

State.prototype.encrypt = function encrypt(body) {
  if (this.writeSession.cipher === null)
    return body;

  var content = Buffer.concat(body);
  var data;
  var session = this.writeSession;

  /*
   * MAC(MAC_write_key, seq_num +
   *                    TLSCompressed.type +
   *                    TLSCompressed.version +
   *                    TLSCompressed.length +
   *                    TLSCompressed.fragment);
   */
  var mac = session.mac(session.macWriteKey)
      .update(content)
      .digest('buffer');

  if (session.info.bulk.cbc) {
    /*
     * struct {
     *      opaque IV[SecurityParameters.record_iv_length];
     *      block-ciphered struct {
     *          opaque content[TLSCompressed.length];
     *          opaque MAC[SecurityParameters.mac_length];
     *          uint8 padding[GenericBlockCipher.padding_length];
     *          uint8 padding_length;
     *      };
     *  } GenericBlockCipher;
     */
    var size = content.length + mac.length + 1;
    var bulkSize = session.info.bulk.size / 8;
    var pad;
    if (size % bulkSize === 0)
      pad = new Buffer(1);
    else
      pad = new Buffer(bulkSize - (size % bulkSize) + 1);
    pad.fill(pad.length - 1);

    var inp = Buffer.concat([ content, mac, pad ]);
    var out = new Buffer(inp.length);
    session.cipher.write(out, inp);

    data = [ this.crypto.random(session.recordIVLength / 8), out ];
  } else {
    throw new Error('Unsupported cipher type');
  }

  // Prepend header
  var total = 0;
  for (var i = 0; i < data.length; i++)
    total += data[i].length;
  var header = new Buffer(5);
  content.copy(header, 0, 3);
  header.writeUInt16BE(total, 3, true);

  return [ header ].concat(data);
};

State.prototype.switchToPending = function switchToPending(side) {
  if (side === 'read')
    this.readSession = this.pending;
  else
    this.writeSession = this.pending;

  this.pending.computeMaster();

  // Reset state
  if (this.readSession === this.pending && this.writeSession === this.pending)
    this.pending = new Session(this);

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
                         session.hashMessages())
                    .read(session.info.verifyLength);
};

//
// Dummy state
//
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

Dummy.prototype.decrypt = function decrypt(body) {
  if (this.encrypted)
    throw new Error('Dummy can\'t decrypt');
  return null;
};

Dummy.prototype.encrypt = function encrypt(body) {
  if (this.encrypted)
    throw new Error('Dummy can\'t encrypt');
  return body;
};

State.createDummy = function createDummy() {
  return new Dummy();
};
