var tls = require('../tls');
var assert = require('assert');
var stream = require('stream');
var util = require('util');
var Buffer = require('buffer').Buffer;
var WriteBuffer = require('wbuf');

var constants = tls.constants;

function Framer(state) {
  stream.Readable.call(this);

  this.state = state;
}
util.inherits(Framer, stream.Readable);
module.exports = Framer;

Framer.create = function create(state) {
  return new Framer(state);
};

Framer.prototype._read = function() {
  // Do nothing
};

Framer.prototype.record = function record(type, length, chunks) {
  // TODO(indutny): Compression hooks
  var recordType = constants.recordTypeByName[type];
  var res = new Buffer(5);

  res[0] = recordType;
  res.writeUInt16BE(this.state.version, 1, true);

  // NOTE: state could update length
  res.writeUInt16BE(length, 3, true);

  // TODO(indunty): catch exceptions?
  var buffers = this.state.encrypt(chunks, res) || chunks;

  // Update length after encryption to include padding
  this.push(res);
  for (var i = 0; i < buffers.length; i++)
    this.push(buffers[i]);

  return buffers;
};

var cipherSpec = new Buffer([1]);

Framer.prototype.changeCipherSpec = function changeCipherSpec() {
  this.record('change_cipher_spec', cipherSpec.length, [ cipherSpec ]);
};

Framer.prototype.alert = function alert(level, description) {
  var body = new Buffer(2);
  body[0] = constants.alertLevelByName[level];
  body[1] = constants.alertDescriptionByName[description];
  this.record('alert', body.length, [ body ]);
};

Framer.prototype._handshakeStart = function _start(size) {
  var buf = new WriteBuffer();
  buf.reserve(4 + size);

  // Header
  buf.skip(4);

  return buf;
};

Framer.prototype._handshake = function handshake(type, len, extLen, chunks) {
  var head = chunks[0];
  assert(head.length >= 4);

  // 24 bits of length (excluding this header)
  head.writeUInt32BE(len + extLen - 4, 0, true);
  head[0] = constants.handshakeTypeByName[type];

  this.record('handshake', len + extLen, chunks);

  // Accumulate state for `verifyData` hash
  if (type !== 'hello_request')
    this.emit('handshakeMsg', chunks);
};

Framer.prototype.hello = function hello(type, hello) {
  // Estimate size to fit data in one buffer
  // version + random + session-len + cipher-count/cipher
  var size = 2 + 32 + 1 + (hello.session ? hello.session.length : 0) + 2;
  if (type === 'client') {
    // Ciphers
    size += hello.cipherSuites.length * 2;

    // Compression
    size += 1;
    if (hello.compressionMethods)
      size += hello.compressionMethods.length;
  } else {
    // Compression
    size += 1;
  }

  var extLen = 0;
  if (hello.extensions)
    for (var i = 0; i < hello.extensions.length; i++)
      extLen += 4 + hello.extensions[i].body.length;

  // Length of extensions section
  if (extLen !== 0)
    size += 2;
  size += extLen;

  var buf = this._handshakeStart(size);

  // Version
  buf.writeUInt16BE(hello.version || this.state.version);

  // Random
  if (hello.random) {
    var random = hello.random;
  } else {
    var random = this.state.crypto.random(32);
    random.writeUInt32BE(+new Date, 0, true);
  }
  buf.copyFrom(random);
  this.emit('random', random);

  // Session length
  if (hello.session) {
    buf.writeUInt8(hello.session.length);
    assert(hello.session.length < 32);
    buf.copyFrom(hello.session);
  } else {
    buf.writeUInt8(0);
  }

  // Cipher suites
  if (type === 'client') {
    buf.writeUInt16BE(hello.cipherSuites.length * 2);
    for (var i = 0; i < hello.cipherSuites.length; i++) {
      var cipher = constants.cipherSuiteByName[hello.cipherSuites[i]];
      buf.writeUInt16BE(cipher);
    }
  } else {
    var cipher = constants.cipherSuiteByName[hello.cipherSuite];
    buf.writeUInt16BE(cipher);
  }

  // Compression methods
  if (type === 'client') {
    if (hello.compressionMethods && hello.compressionMethods.length > 0) {
      buf.writeUInt8(hello.compressionMethods.length);
      for (var i = 0; i < hello.compressionMethods.length; i++) {
        buf.writeUInt8(
          constants.compressionMethodByName[hello.compressionMethods[i]]);
      }
    } else {
      // No compression
      buf.writeUInt16BE(0x0100);
    }
  // Server compression methods
  } else {
    if (hello.compressionMethod) {
      var comp = constants.compressionMethodByName[hello.compressionMethod];
      buf.writeUInt8(comp);
    } else {
      // No compression
      buf.writeUInt8(0);
    }
  }

  // Extensions
  if (extLen !== 0) {
    buf.writeUInt16BE(extLen);
    for (var i = 0; i < hello.extensions.length; i++)
      this._helloExtension(hello.extensions[i], buf);
  }

  this._handshake(type === 'client' ? 'client_hello' : 'server_hello',
                  buf.size - extLen,
                  extLen,
                  buf.render());
};

Framer.prototype._helloExtension = function helloExtension(extension, buf) {
  var type = constants.extensionTypeByName[extension.type];
  var body = extension.body;

  buf.writeUInt16BE(type);
  buf.writeUInt16BE(body.length);
};

Framer.prototype.certificate = function certificate(certs) {
  var content = [];

  var size = 0;
  for (var i = 0; i < certs.length; i++)
    size += 3 + certs[i].length;

  var buf = this._handshakeStart(size + 3);
  buf.writeUInt24BE(size);
  for (var i = 0; i < certs.length; i++) {
    var cert = certs[i];

    buf.writeUInt24BE(cert.length);
    buf.copyFrom(cert);
  }

  this._handshake('certificate', buf.size, 0, buf.render());
};

Framer.prototype.keyExchange = function keyExchange(type, data) {
  var buf = this._handshakeStart(data.length);
  buf.copyFrom(data);

  this._handshake(type === 'client' ? 'client_key_exchange' :
                                      'server_key_exchange',
                  buf.size,
                  0,
                  buf.render());
};

Framer.prototype.certificateRequest = function certificateRequest(options) {
  var size = 0;

  // Certificate types
  size += 1 + options.types.length;

  // Sign and hash
  size += 2 + 2 * options.signatureAlgorithms.length;

  var authLen = 0;
  for (var i = 0; i < options.authorities.length; i++)
    authLen += 2 + options.authorities[i].length;
  if (authLen !== 0)
    size += 2 + authLen;

  var buf = this._handshakeStart(size);

  // Client certificate types
  buf.writeUInt8(options.types.length);
  for (var i = 0; i < options.types.length; i++)
    buf.writeUInt8(constants.clientCertTypeByName[options.types[i]]);

  // Signature and hash algorithms
  buf.writeUInt16BE(options.signatureAlgorithms.length * 2);
  for (var i = 0; i < options.signatureAlgorithms.length; i++) {
    var alg = options.signatureAlgorithms[i];
    buf.writeUInt8(constants.hashAlgorithmByName[alg.hash]);
    buf.writeUInt8(constants.signatureAlgorithmByName[alg.sign]);
  }

  // Authorities list
  if (authLen !== 0) {
    buf.writeUInt16BE(authLen);
    for (var i = 0; i < options.authorities.length; i++) {
      var name = options.authorities[i];
      buf.writeUInt16BE(name.length);
      buf.copyFrom(name);
    }
  }

  this._handshake('certificate_request', buf.size, 0, buf.render());
};

Framer.prototype.helloDone = function helloDone() {
  var buf = this._handshakeStart(0);
  this._handshake('server_hello_done', buf.size, 0, buf.render());
};

Framer.prototype.helloRequest = function helloRequest() {
  var buf = this._handshakeStart(0);
  this._handshake('hello_request', buf.size, 0, buf.render());
};

Framer.prototype.finished = function finished(verify) {
  var buf = this._handshakeStart(verify.length);
  buf.copyFrom(verify);
  this._handshake('finished', buf.size, 0, buf.render());
};

Framer.prototype.appData = function appData(data) {
  this.record('application_data', data.length, [ data ]);
};

//
// State framers
//

Framer.prototype.signature = function signature(params, s) {
  if (this.state.version >= 0x0303) {
    var hash = constants.hashAlgorithmByName[params.hash];
    var sign = constants.signatureAlgorithmByName[params.signature];

    var out = new Buffer(2 + 2 + s.length);
    out[0] = hash;
    out[1] = sign;
    out.writeUInt16BE(s.length, 2, true);

    s.copy(out, 4);
  } else {
    // TLS < 1.2 doesn't have sig/alg fields
    var out = new Buffer(2 + s.length);
    out.writeUInt16BE(s.length, 0, true);

    s.copy(out, 2);
  }

  return out;
};

Framer.prototype.ECDHEServerKeyEx = function ECDHEServerKeyEx(params, point) {
  assert.equal(params.type, 'named_curve');

  var type = constants.curveTypeByName[params.type];
  var curve = constants.namedCurveByName[params.value];
  assert(type && curve);

  var out = new Buffer(3 + 1 + point.length);
  out[0] = type;
  out.writeUInt16BE(curve, 1, true);

  assert(point.length <= 255);
  out[3] = point.length;

  point.copy(out, 4);

  return out;
};
