var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var rfc3280 = require('asn1.js-rfc3280');

var tls = require('../tls');
var utils = tls.utils;

function Session(state) {
  this.state = state;
  this.id = null;

  this.readSeq = new Buffer(8);
  this.readSeq.fill(0);
  this.writeSeq = new Buffer(8);
  this.writeSeq.fill(0);

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
  this.compression = null;
  this.preMaster = null;
  this.masterSecret = null;
  this.clientRandom = null;
  this.serverRandom = null;
  this.verify = null;

  // Keys
  this.clientWriteMacKey = null;
  this.serverWriteMacKey = null;
  this.macReadKey = null;
  this.macWriteKey = null;
  this.clientWriteKey = null;
  this.serverWriteKey = null;
  this.clientWriteIV = null;
  this.serverWriteIV = null;

  // Key Exchange
  this.clientKeyEx = null;
  this.serverKeyEx = null;

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

  var rrandoms = Buffer.concat([ this.serverRandom, this.clientRandom ]);
  var keyBlock = this.prf(this.masterSecret, 'key expansion', rrandoms);

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
  this.hash = crypto.hash(info.prf);
  this.macKeyLength = info.macSize;
  this.fixedIVLength = info.bulk.ivSize;

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
  this.minVersion = this.context.minVersion || { major: 3, minor: 1 };
  this.maxVersion = this.context.maxVersion || { major: 3, minor: 3 };
  this.version = this.maxVersion;
  this.secure = false;

  // TODO(indutny): more default ciphers?
  this.ciphers = this.options.ciphers || this.context.ciphers || [
    'TLS_RSA_WITH_AES_256_CBC_SHA'
  ];
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

  this.framer.on('error', function(err) {
    // TODO(indutny): figure out errors in parser
    self._error(err.description || 'internal_error', err);
  });

  this.parser.on('error', function(err) {
    // TODO(indutny): figure out errors in parser
    self._error(err.description || 'unexpected_message', err);
  });
};
util.inherits(State, EventEmitter);
module.exports = State;

State.create = function create(options) {
  return new State(options);
};

State.prototype.start = function start() {
  if (this.type !== 'client')
    return;

  this.framer.hello('client', {
    session: this.pending.id,
    cipherSuites: this.getCipherSuites()
  });
};

State.prototype.handle = function handle(frame) {
  if (this.wait !== 'hello' &&
      (frame.version.minor !== this.version.minor ||
       frame.version.major !== this.version.major)) {
    return this._error('protocol_version', 'Invalid version after handshake');
  }

  // NOTE: We are doing it not in parser, because parser may parse more
  // frames that we have yet observed.
  // Accumulate state for `verifyData` hash
  // TODO(indutny) renegotiation
  if (!this.secure &&
      frame.type === 'handshake' &&
      frame.handshakeType !== 'hello_request') {
    this.pending.addHandshakeMessage([ frame.rawBody ]);
  }

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
    else if (frame.type === 'application_data')
      handled = this.handleAppData(frame);

    if (start !== this.wait)
      this.emit('stateChange', start, this.wait);
  } while (handled === this.skip);

  return handled;
};

//
// Common parts
//

State.prototype.handleAlert = function handleAlert(frame) {
  if (frame.level === 'fatal') {
    var err = new Error('Received alert: ' + frame.description);
    this.emit('error', err);
    return true;
  }

  // EOF, handled by socket
  if (frame.description === 'close_notify')
    return true;

  // TODO(indutny): Handle not fatal alerts
  return true;
};

State.prototype.handleHandshake = function handleHandshake(frame) {
  if (this.type === 'client')
    return this.clientHandleHandshake(frame);
  else
    return this.serverHandleHandshake(frame);
};

State.prototype.handleChangeCipher = function handleChangeCipher() {
  // Parser already handles it
  return true;
};

State.prototype.handleAppData = function handleAppData(frame) {
  // App data is not allowed in handshake
  if (!this.secure)
    return false;

  // Handled in socket.js
  return true;
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

    // TODO(indutny): DHE
    if (this.pending.info.dh === 'ecdhe')
      this.wait = 'ecdheKeyExchange';
    else
      this.wait = 'certReq';
  } else if (this.wait === 'ecdheKeyExchange') {
    if (htype !== 'server_key_exchange')
      return false;

    if (!this.clientHandleECDHEKeyEx(frame))
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
    if (!this.clientHandleHelloDone(frame))
      return false;

    this.wait = 'finished';
  } else if (this.wait === 'finished'){
    if (htype !== 'finished' || !this.bothSwitched())
      return false;

    if (!this.checkFinished(frame))
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

State.prototype.checkFinished = function checkFinished(frame) {
  if (!this.readSession.verify)
    return false;

  if (this.readSession.verify.toString('hex') ===
      frame.verify.toString('hex')) {
    return true;
  }

  // Do not leak memory
  this.readSession.verify = null;

  return this._error('bad_record_mac', e);
};

State.prototype.clientHandleHello = function clientHandleHello(frame) {
  this.setReceivedRandom(frame.random.raw);
  if (!this.selectCipherSuite([ frame.cipherSuite ]))
    return false;

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
    return this._error('bad_certificate', e);
  }

  var leaf = utils.getLeaf(this.crypto, certs);
  if (!leaf)
    return this._error('certificate_unknown', 'No leaf certificate available');

  this.key = {
    key: null,
    certs: frame.certs,
    leaf: leaf,
    pub: leaf.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
  };
  this.emit('cert', leaf, frame.certs);

  return true;
};

State.prototype.clientHandleHelloDone = function clientHandleHelloDone(frame) {
  // Anonymous ciphers
  if (this.pending.info.auth === 'anon' || this.pending.info.auth === 'null')
    return true;

  // TODO(indutny): Certificate requests

  // TODO(indunty): async may be?

  // TODO(indutny): Support non-RSA ciphers
  // TODO(indutny): Support DHE?
  var res;
  if (this.pending.info.dh === 'ecdhe')
    res = this.clientECDHEKeyEx();
  else
    res = this.clientRSAKeyEx();
  if (!res)
    return false;

  this.changeCipherAndFinish();

  return true;
};

State.prototype.clientECDHEKeyEx = function clientECDHEKeyEx() {
  // Missing ServerKeyExchange
  // TODO(indutny): proper error?
  if (!this.pending.serverKeyEx)
    return false;

  var params = this.pending.serverKeyEx.params;

  try {
    var pairs = {
      client: this.crypto.genECDHEPair(params),
      server: this.crypto.toECDHEPub(params, this.pending.serverKeyEx.point)
    };

    var secret = this.crypto.deriveECDHE(pairs.client, pairs.server);
  } catch (e) {
    return this._error('internal_error', e);
  }

  this.pending.preMaster = secret;

  var pub = this.crypto.getECDHEPub(pairs.client);
  assert(pub.length <= 255);
  var prefix = new Buffer([ pub.length ]);
  var content = Buffer.concat([ prefix, pub ], pub.length + 1);
  this.framer.keyExchange('client', content);

  return true;
};

State.prototype.clientRSAKeyEx = function clientRSAKeyEx() {
  if (this.pending.info.auth !== 'rsa')
    return false;

  var size = 46;
  var preMaster = new Buffer(2 + size);
  preMaster[0] = this.version.major;
  preMaster[1] = this.version.minor;
  this.crypto.random(46).copy(preMaster, 2);

  this.pending.preMaster = preMaster;

  var content = this.crypto.encryptPublic(preMaster, this.key.pub);

  var prefix = new Buffer(2);
  prefix.writeUInt16BE(content.length, 0, true);
  content = Buffer.concat([ prefix, content ]);
  this.framer.keyExchange('client', content);

  return true;
};

State.prototype.clientHandleECDHEKeyEx =
    function clientHandleECDHEKeyEx(frame) {
  var keyEx = this.parser.parseECDHEKeyEx(frame);
  if (!keyEx)
    return false;

  if (keyEx.params.type !== 'named_curve')
    return false;

  // Algorithms should match
  if (this.pending.info.auth !== keyEx.signature.signature)
    return this._error('bad_record_mac', 'Signature algorithm doesn\'t match');

  if (this.key === null)
    return false;

  // TODO(indutny): Figure out situations, where cert has different hash
  // function
  try {
    var v = this.crypto.verify(keyEx.signature)
                       .update(this.pending.clientRandom)
                       .update(this.pending.serverRandom)
                       .update(keyEx.rawParams)
                       .verify(this.crypto.toVerifyKey(this.key.pub),
                               keyEx.signature.content);
  } catch (e) {
    return this._error('bad_record_mac', e);
  }
  if (!v)
    return this._error('bad_record_mac', 'Bad signature');

  this.pending.serverKeyEx = keyEx;

  return true;
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

    if (this.pending.info.dh === 'ecdhe')
      this.wait = 'ecdheKeyExchange';
    else
      this.wait = 'keyExchange';
  } else if (this.wait === 'certificate') {
    if (htype !== 'certificate') {
      this.wait = 'keyExchange';
      return this.skip;
    }

    this.wait = 'keyExchange';
  } else if (this.wait === 'ecdheKeyExchange') {
    if (htype !== 'client_key_exchange')
      return false;

    if (!this.serverHandleECDHEKeyEx(frame))
      return false;

    this.wait = 'certVerify';
  } else if (this.wait === 'keyExchange') {
    if (htype !== 'client_key_exchange')
      return false;

    if (!this.serverHandleRSAKeyEx(frame))
      return false;

    this.wait = 'certVerify';
  } else if (this.wait === 'certVerify') {
    if (htype !== 'certificate_verify') {
      this.wait = 'finished';
      return this.skip;
    }

    this.wait = 'finished';
  } else if (this.wait === 'finished') {
    // TODO(indutny): renegotiation?
    if (htype !== 'finished' || this.bothSwitched())
      return false;

    if (!this.checkFinished(frame))
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
  var cipher = this.selectCipherSuite(frame.cipherSuites);
  if (!cipher)
    return;

  if (!this.negotiateVersion(frame.helloVersion) &&
      !this.negotiateVersion(frame.version)) {
    return this._error('protocol_version', 'Server failed to negotiate ver');
  }

  this.setReceivedRandom(frame.random.raw);
  this.framer.hello('server', {
    cipherSuite: cipher
  });

  if (this.key !== null)
    this.framer.certificate(this.key.certs);

  // TODO(indutny): Server key exchange for DHE, CertificateRequest
  var res = true;
  if (this.pending.info.dh === 'ecdhe')
    res = this.serverECDHEKeyEx(frame);
  if (!res)
    return false;

  this.framer.helloDone();

  return true;
};

State.prototype.serverECDHEKeyEx = function serverECDHEKeyEx(hello) {
  if (this.key === null)
    return this._error('internal_error', 'No key found');

  // TODO(indutny): Support ECDSA signatures
  if (this.pending.info.auth !== 'rsa')
    return false;

  // TODO(indutny): Use curves from hello
  var params = {
    type: 'named_curve',
    value: this.context.curve
  };
  try {
    this.pending.serverKeyEx = {
      params: params,
      private: this.crypto.genECDHEPair(params)
    };
  } catch (e) {
    return this._error('internal_error', e);
  }

  var pub = this.crypto.getECDHEPub(this.pending.serverKeyEx.private);
  var content = this.framer.ECDHEServerKeyEx(params, pub);
  if (!content)
    return false;

  var sparams = {
    signature: this.pending.info.auth,
    hash: 'sha1'
  };

  var sign = this.crypto.sign(sparams)
                        .update(this.pending.clientRandom)
                        .update(this.pending.serverRandom)
                        .update(content)
                        .sign(this.key.key);
  var s = this.framer.signature(sparams, sign);
  if (!s)
    return false;

  this.framer.keyExchange('server', Buffer.concat([ content, s ]));
  return true;
};

State.prototype.serverHandleRSAKeyEx = function serverHandleRSAKeyEx(frame) {
  if (this.key === null)
    return false;

  var keyEx = this.parser.parseRSAKeyEx(frame);
  if (!keyEx)
    return false;

  // TODO(indutny): Support DHE
  try {
    this.pending.preMaster = this.crypto.decryptPrivate(keyEx, this.key.key);
  } catch (e) {
    return this._error('decrypt_error', e);
  }

  if (this.pending.preMaster[0] !== this.version.major ||
      this.pending.preMaster[1] !== this.version.minor) {
    this._error('protocol_version', 'client_key_exchange version mismatch');
    return false;
  }

  return true;
};

State.prototype.serverHandleECDHEKeyEx =
    function serverHandleECDHEKeyEx(frame) {
  var point = this.parser.parseECDHEClientKeyEx(frame);
  if (!point)
    return false;

  var params = this.pending.serverKeyEx.params;
  try {
    var pairs = {
      server: this.pending.serverKeyEx.private,
      client: this.crypto.toECDHEPub(params, point)
    };

    var secret = this.crypto.deriveECDHE(pairs.server, pairs.client);
  } catch (e) {
    return this._error('internal_error', e);
  }

  this.pending.preMaster = secret;

  return true;
};

//
// Routines
//

State.prototype._error = function error(description, msg) {
  this.framer.alert('fatal', description);

  var err = msg instanceof Error ? msg : new Error(msg);
  this.emit('error', err);

  return false;
};

State.prototype.changeCipherAndFinish = function changeCipherAndFinish() {
  // Send verify data and clear messages
  this.framer.changeCipherSpec();

  // NOTE: Fetch verify data before clearing the states
  var verifyData;

  // All consecutive writes will be encrypted
  var self = this;
  this.switchToPending('write', function() {
    verifyData = self.getVerifyData('write');

    if (verifyData)
      self.framer.finished(verifyData);
    else
      self._error('unexpected_message', 'Session is not initialized');
  });
};

State.prototype.decrypt = function decrypt(body, header) {
  if (this.readSession.decipher === null)
    return null;

  var session = this.readSession;

  // Decipher data
  var out = new Buffer(body.length);
  session.decipher.write(out, body);

  if (session.info.bulk.cbc) {
    // Remove IV
    var iv = out.slice(0, session.recordIVLength / 8);
    var data = out.slice(iv.length);

    // Remove padding
    var pad = data[data.length - 1];
    if (data.length <= pad + 1)
      throw new Error('Padding OOB');

    for (var i = data.length - pad - 1; i < data.length; i++)
      if (data[i] !== pad)
        throw new Error('Padding bytes are invalid');

    data = data.slice(0, -pad - 1);

    // Remove mac
    var mac = data.slice(-session.macKeyLength / 8);
    var res = data.slice(0, -mac.length);
  } else if (session.info.type === 'stream') {
    var mac = out.slice(-session.macKeyLength / 8);
    var res = out.slice(0, -mac.length);
  } else {
    throw new Error('Unsupported cipher type');
  }

  // Compute expeted MAC
  // 1 - type
  // 2 - version
  // 2 - length
  var pre = new Buffer(1 + 2 + 2);
  header.buffer.copy(pre, 0, 0, 3);
  pre.writeUInt16BE(res.length, 3, true);

  // TODO(indutny): Fix side-channel leak
  var expectedMac = session.mac(session.macReadKey)
      .update(session.readSeq)
      .update(pre)
      .update(res)
      .digest('buffer');
  utils.incSeq(session.readSeq);

  if (mac.toString('hex') !== expectedMac.toString('hex'))
    throw new Error('Invalid MAC');

  return res;
};

State.prototype.encrypt = function encrypt(body, hdr) {
  if (this.writeSession.cipher === null)
    return null;

  var content = Buffer.concat(body);
  var session = this.writeSession;

  // 1 - type
  // 2 - version
  // 2 - length
  var pre = new Buffer(1 + 2 + 2);
  hdr.copy(pre, 0, 0, 5);

  // Compute MAC
  /*
   * MAC(MAC_write_key, seq_num +
   *                    TLSCompressed.type +
   *                    TLSCompressed.version +
   *                    TLSCompressed.length +
   *                    TLSCompressed.fragment);
   */
  var mac = session.mac(session.macWriteKey)
      .update(session.writeSeq)
      .update(pre)
      .update(content)
      .digest('buffer');
  utils.incSeq(session.writeSeq);

  var bulkSize = session.info.bulk.size / 8;
  var length = content.length;
  var padLen = 0;
  if (session.info.bulk.cbc) {
    length += session.recordIVLength / 8;
    length += session.macKeyLength / 8;

    // Padding length byte
    length += 1;

    // Padding length
    if (length % bulkSize !== 0)
      padLen = bulkSize - (length % bulkSize);
    else
      padLen = 0;
    length += padLen;
  } else if (session.info.type === 'stream') {
    length += session.macKeyLength / 8;
  } else {
    throw new Error('Unsupported cipher type');
  }

  // NOTE: Updates length in real record header
  hdr.writeUInt16BE(length, 3, true);

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
    var pad = new Buffer(padLen + 1);
    pad.fill(pad.length - 1);

    var iv = this.crypto.random(session.recordIVLength / 8);

    var inp = Buffer.concat([ iv, content, mac, pad ]);
  } else if (session.info.type === 'stream') {
    /*
     * stream-ciphered struct {
     *     opaque content[TLSCompressed.length];
     *     opaque MAC[SecurityParameters.mac_length];
     * } GenericStreamCipher;
     */
    var inp = Buffer.concat([ content, mac ]);
  } else {
    throw new Error('Unsupported cipher type');
  }

  var out = new Buffer(inp.length);
  session.cipher.write(out, inp);
  return [ out ];
};

State.prototype.switchToPending = function switchToPending(side, cb) {
  if (side === 'read')
    this.readSession = this.pending;
  else
    this.writeSession = this.pending;

  this.pending.computeMaster();

  if (cb)
    cb();

  if (side === 'read')
    this.pending.verify = this.getVerifyData('read');

  // Reset state
  if (this.readSession === this.pending && this.writeSession === this.pending) {
    this.pending.clearMessages();
    this.pending = new Session(this);
  }

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
  for (var i = 0; i < this.ciphers.length; i++) {
    var our = this.ciphers[i];
    for (var j = 0; j < ciphers.length; j++) {
      var their = ciphers[j];
      if (our === their) {
        var cipher = our;

        this.pending.load(this.crypto, cipher);

        // TODO(indunty): Support ECDSA
        if (this.pending.info.auth !== 'rsa')
          return false;

        this.key = this.context.keys[this.pending.info.auth] || null;
        return cipher;
      }
    }
  }

  return false;
};

State.prototype.getVerifyData = function getVerifyData(side) {
  var session = side === 'read' ? this.readSession : this.writeSession;

  // Not initialized
  if (session.prf === null ||
      session.mac === null ||
      session.masterSecret === null) {
    return null;
  }

  var label;
  if (this.type === 'client' && side === 'write' ||
      this.type === 'server' && side === 'read') {
    label = 'client finished';
  } else {
    label = 'server finished';
  }

  return new session.prf(session.masterSecret,
                         label,
                         session.hashMessages())
                    .read(session.info.verifyLength);
};

State.prototype.negotiateVersion = function negotiateVersion(v) {
  if (v.major < this.minVersion.major || v.major > this.maxVersion.major)
    return false;
  if (v.major === this.minVersion.major && v.minor < this.minVersion.minor)
    return false;
  if (v.major === this.maxVersion.major && v.minor > this.maxVersion.minor)
    return false;

  // NOTE: Important to clone, but could use `v`
  this.version = { major: v.major, minor: v.minor };

  return true;
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

Dummy.prototype.switchToPending = function switchToPending(side, cb) {
  this.encrypted = true;
  if (cb)
    cb();
};

Dummy.prototype.decrypt = function decrypt(body) {
  if (this.encrypted)
    throw new Error('Dummy can\'t decrypt');
  return null;
};

Dummy.prototype.encrypt = function encrypt(body) {
  if (this.encrypted)
    throw new Error('Dummy can\'t encrypt');
  return null;
};

State.createDummy = function createDummy() {
  return new Dummy();
};
