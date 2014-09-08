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

Framer.prototype.record = function record(type, size, cb) {
  var wb = new WriteBuffer();

  // Ensure that first chunk will be a separate buffer
  if (this.state.shouldEncrypt())
    wb.reserve(5);
  else
    wb.reserve(5 + size);

  var header = wb.skip(5);
  var prefixSize = wb.size;

  if (this.state.shouldEncrypt())
    wb.reserve(size);

  cb.call(this, wb);

  // TODO(indutny): Compression hooks
  header.writeUInt8(constants.recordTypeByName[type]);
  header.writeUInt16BE(this.state.version);

  // NOTE: state could update length in encryption
  header.writeUInt16BE(wb.size - prefixSize);

  // TODO(indunty): catch exceptions?
  var chunks = wb.render();
  if (this.state.shouldEncrypt()) {
    var header = chunks[0];
    assert.equal(header.length, prefixSize);
    var buffers = [
      header
    ].concat(this.state.encrypt(chunks.slice(1), header));
  } else {
    var buffers = chunks;
  }

  // Update length after encryption to include padding
  for (var i = 0; i < buffers.length; i++)
    this.push(buffers[i]);

  return buffers;
};

Framer.prototype.changeCipherSpec = function changeCipherSpec() {
  this.record('change_cipher_spec', 1, function(buf) {
    buf.writeUInt8(1);
  });
};

Framer.prototype.alert = function alert(level, description) {
  this.record('alert', 2, function(buf) {
    buf.writeUInt8(constants.alertLevelByName[level]);
    buf.writeUInt8(constants.alertDescriptionByName[description]);
  });
};

Framer.prototype.handshake = function handshake(type, size, cb) {
  this.record('handshake', 4 + size, function(buf) {
    var entrySize = buf.size;

    var header = buf.skip(4);
    var prefixSize = buf.size;

    var len = cb.call(this, buf);

    header.writeUInt8(constants.handshakeTypeByName[type]);
    header.writeUInt24BE(buf.size - prefixSize);

    // Accumulate state for `verifyData` hash
    if (type !== 'hello_request') {
      var chunks = buf.render().slice();
      assert(chunks[0].length >= entrySize);
      chunks[0] = chunks[0].slice(entrySize);
      this.emit('handshakeMsg', chunks);
    }
  });
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

  var htype = type === 'client' ? 'client_hello' : 'server_hello';
  this.handshake(htype, size, function(buf) {
    // Version
    buf.writeUInt16BE(hello.maxVersion || this.state.version);

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

    return extLen;
  });
};

Framer.prototype._helloExtension = function helloExtension(extension, buf) {
  var type = constants.extensionTypeByName[extension.type];
  var body = extension.body;

  buf.writeUInt16BE(type);
  buf.writeUInt16BE(body.length);
  buf.copyFrom(body);
};

Framer.prototype.certificate = function certificate(certs) {
  var content = [];

  var size = 0;
  for (var i = 0; i < certs.length; i++)
    size += 3 + certs[i].length;

  this.handshake('certificate', size, function(buf) {
    buf.writeUInt24BE(size);
    for (var i = 0; i < certs.length; i++) {
      var cert = certs[i];

      buf.writeUInt24BE(cert.length);
      buf.copyFrom(cert);
    }

    return 0;
  });
};

Framer.prototype.keyExchange = function keyExchange(type, data) {
  var htype = type === 'client' ? 'client_key_exchange' : 'server_key_exchange';
  this.handshake(htype, data.length, function(buf) {
    buf.copyFrom(data);

    return 0;
  });
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

  this.handshake('certificate_request', size, function(buf) {
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

    return 0;
  });
};

Framer.prototype.helloDone = function helloDone() {
  this.handshake('server_hello_done', 0, function() {
    return 0;
  });
};

Framer.prototype.helloRequest = function helloRequest() {
  this.handshake('hello_request', 0, function() {
    return 0;
  });
};

Framer.prototype.finished = function finished(verify) {
  this.handshake('finished', verify.length, function(buf) {
    buf.copyFrom(verify);
    return 0;
  });
};

Framer.prototype.appData = function appData(data) {
  this.record('application_data', data.length, function(buf) {
    buf.copyFrom(data);
  });
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
