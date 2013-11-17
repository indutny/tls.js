var tls = require('../tls');
var assert = require('assert');
var crypto = require('crypto');
var stream = require('stream');
var util = require('util');

var constants = tls.constants;

function Framer(state) {
  stream.Readable.call(this);

  if (state instanceof tls.state)
    this.state = state;
  else
    this.state = tls.state.create(state);
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
  // TODO(indutny): Compression and encryption hooks
  var recordType = constants.recordTypeByName[type];
  var res = new Buffer(5);

  res[0] = recordType;
  res[1] = this.state.version.major,
  res[2] = this.state.version.minor,
  res.writeUInt16BE(length, 3, true);

  this.push(res);
  for (var i = 0; i < chunks.length; i++)
    this.push(chunks[i]);
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

var noComp = new Buffer([0]);

Framer.prototype._handshake = function handshake(type, len, extLen, chunks) {
  var head = new Buffer(4);
  head.writeUInt32BE(len, 0, true);
  head[0] = constants.handshakeTypeByName[type];

  this.record('handshake', head.length + len + extLen, [ head ].concat(chunks));
};

Framer.prototype.hello = function hello(type, hello) {
  var content = [];
  var len = 0;

  // version + random + session-len
  var pre = new Buffer(2 + 32 + 1);
  content.push(pre);
  len += pre.length;

  // Version
  pre[0] = (hello.version || this.state.version).major;
  pre[1] = (hello.version || this.state.version).minor;

  // Random: unix time
  pre.writeUInt32BE(+new Date, 2, true);
  // Random: random data
  crypto.randomBytes(28).copy(pre, 6);

  // Emit choosen random
  this.emit('random', pre.slice(2, 2 + 32));

  // Session length
  if (hello.session) {
    pre[pre.length - 1] = hello.session.length;
    assert(hello.session.length < 32);
    content.push(hello.session);
    len += hello.session.length;
  } else {
    pre[pre.length - 1] = 0;
  }

  // Cipher suites
  if (type === 'client') {
    var cipherSuites = new Buffer(2 + hello.cipherSuites.length * 2);
    content.push(cipherSuites);
    len += cipherSuites.length;

    cipherSuites.writeUInt16BE(hello.cipherSuites.length * 2, 0, true);
    for (var i = 0; i < hello.cipherSuites.length; i++) {
      var cipher = constants.cipherSuiteByName[hello.cipherSuites[i]];
      cipher.copy(cipherSuites, i * 2 + 2);
    }
  } else {
    var cipher = constants.cipherSuiteByName[hello.cipherSuite];
    content.push(cipher);
    len += cipher.length;
  }

  // Compression methods
  if (hello.compressions) {
    var compMethods = new Buffer(1 + hello.compressions.length);
    content.push(compMethods);
    len += compMethods.length;

    compMethods[0] = hello.compression.length;
    for (var i = 0; i < hello.compressions.length; i++)
      compMethods[i + 1] = hello.compressions[i];
  } else {
    content.push(noComp);
    len += noComp.length;
  }

  // Extensions
  var extensionsLen = 0;
  if (hello.extensions) {
    for (var i = 0; i < hello.extensions.length; i++) {
      var extension = this._helloExtension(hello.extensions[i]);
      content.push(extension);
      extensionsLen += extension.length;
    }
  }

  this._handshake(type === 'client' ? 'client_hello' : 'server_hello',
                  len,
                  extensionsLen,
                  content);
};

Framer.prototype._helloExtension = function helloExtension(extension) {
  throw new Error('Not implemented');
};

Framer.prototype.certificate = function certificate(certs) {
  var content = [];
  var len = 0;
  var total = 0;

  for (var i = 0; i < certs.length; i++) {
    var cert = certs[i];
    var certHead = new Buffer(3);
    certHead[0] = (cert.length >> 16) & 0xff;
    certHead.writeUInt16BE(cert.length & 0xffff, 1, true);
    content.push(certHead);
    content.push(cert);
    total += certHead.length + cert.length;
  }

  var head = new Buffer(3);
  head[0] = (total >> 16) & 0xff;
  head.writeUInt16BE(total & 0xffff, 1, true);

  this._handshake('certificate',
                  head.length + total,
                  0,
                  [head].concat(content));
};

Framer.prototype.keyExchange = function keyExchange(algorithm, params) {
  throw new Error('Not implemented');
};

Framer.prototype.certificateRequest = function certificateRequest(options) {
  var content = [];
  var len = 0;

  // Client certificate types
  var types = new Buffer(1 + options.types.length);
  content.push(types);
  len += types.length;

  types[0] = options.types.length;
  for (var i = 0; i < options.types.length; i++)
    types[i + 1] = constants.clientCertTypeByName[options.types[i]];

  // Signature and hash algorithms
  var signAndHash = new Buffer(2 + 2 * options.signatureAlgorithms.length);
  content.push(signAndHash);
  len += signAndHash.length;

  signAndHash.writeUInt16BE(options.signatureAlgorithms.length * 2, 0, true);
  for (var i = 0; i < options.signatureAlgorithms.length; i++) {
    var alg = options.signatureAlgorithms[i];
    signAndHash[2 + i * 2] = constants.hashAlgorithmByName[alg.hash];
    signAndHash[2 + i * 2 + 1] = constants.signatureAlgorithmByName[alg.sign];
  }

  // Authorities list
  var authList = [];
  var total = 0;
  for (var i = 0; i < options.authorities.length; i++) {
    var name = options.authorities[i];
    var size = new Buffer(2);
    size.writeUInt16BE(name.length, 0, true);
    authList.push(size);
    authList.push(name);
    total += size.length + name.length;
  }
  var auth = new Buffer(2);
  auth.writeUInt16BE(total, 0, true);

  content.push(auth);
  content = content.concat(authList);
  len += auth.length;
  len += total;

  this._handshake('certificate_request', len, 0, content);
};

Framer.prototype.helloDone = function helloDone() {
  this._handshake('server_hello_done', 0, 0, []);
};

Framer.prototype.helloRequest = function helloRequest() {
  this._handshake('hello_request', 0, 0, []);
};

Framer.prototype.finished = function finished(verify) {
  this._handshake('finished', verify.length, 0, verify);
};
