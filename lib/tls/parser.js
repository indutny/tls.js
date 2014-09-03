var tls = require('../tls');
var stream = require('stream');
var util = require('util');
var Buffer = require('buffer').Buffer;
var OffsetBuffer = require('obuf');

var constants = tls.constants;

function Parser(state) {
  stream.Transform.call(this);
  this._readableState.objectMode = true;

  // Propagate pressure properly, and don't parse way too much
  this._readableState.highWaterMark = 1;

  this.state = state;

  this.buffer = new OffsetBuffer();
  this.handshakeBuffer = null;

  this.header = false;
  this.body = false;
  this.rawBody = false;
}
util.inherits(Parser, stream.Transform);
module.exports = Parser;

Parser.create = function create(state) {
  return new Parser(state);
};

Parser.prototype._transform = function transform(data, encoding, callback) {
  var buffer = this.buffer;
  buffer.push(data);

  var err = null;
  while (true) {
    // If we have enough bytes to feast
    if (!this.header) {
      if (!buffer.has(5))
        break;

      this.header = {
        buffer: buffer.clone(5),
        type: constants.recordType[buffer.readUInt8()],
        version: buffer.readUInt16BE(),
        length: buffer.readUInt16BE()
      };

      // Record length must not exceed 2^14 + 2048
      // NOTE: additional 2048 might be introduced in TLSCipherText
      if (this.header.length > 18432) {
        err = new Error('Invalid record length');
        this.header = null;
      }
    }

    // NOTE: header may be set in previous if clause
    if (this.header) {
      var len = this.header.length;
      if (!buffer.has(len))
        break;

      // TODO(indunty): coalesce data from multiple records?
      var self = this;
      var decrypted = true;
      if (this.state.shouldDecrypt()) {
        var input = buffer.take(len);
        this.body = new OffsetBuffer();

        try {
          this.body.push(this.state.decrypt(input, this.header));
        } catch (e) {
          // Report raw Encrypted records when using dummy state
          if (this.state instanceof tls.state.Dummy) {
            decrypted = false;
          } else {
            err = e;
            err.description = 'bad_record_mac';
            break;
          }
        }
        if (decrypted) {
          this.rawBody = this.body.clone(this.body.size);
        } else {
          this.body.push(input);
          this.rawBody = this.body;
        }
      } else {
        this.rawBody = buffer.clone(len);
        this.body = this.rawBody.clone(len);
        buffer.skip(len);
      }

      if (decrypted)
        err = this.parseBody();
      else
        this.push(new EncryptedRecord(this, this.rawBody));

      this.header = false;
      this.body = false;
    }
    if (err)
      break;
  }

  if (err && !err.description)
    err.description = 'decode_error';
  callback(err);
};

Parser.prototype.parseBody = function parseBody() {
  var err;

  if (this.header.type === 'application_data')
    err = this.parseApplicationData();
  else if (this.header.type === 'alert')
    err = this.parseAlert();
  else if (this.header.type === 'handshake')
    err = this.parseHandshake();
  else if (this.header.type === 'change_cipher_spec')
    err = this.parseChangeCipherSpec();
  else if (this.header.type === 'heartbeat')
    err = this.parseHeartbeat();
  else
    err = new Error(this.header.type + ' is not supported yet');

  return err;
};

function Record(parser) {
  this.version = parser.header.version;
  this.rawBody = parser.rawBody;
}

function EncryptedRecord(parser, body) {
  Record.call(this, parser);
  this.type = 'encrypted';
  this.data = body;
}

function ApplicationData(parser, body) {
  Record.call(this, parser);
  this.type = 'application_data';
  this.chunks = body;
}
util.inherits(ApplicationData, Record);

Parser.prototype.parseApplicationData = function parseApplicationData() {
  this.push(new ApplicationData(this, this.body.toChunks()));

  return null;
};

function Alert(parser, level, description) {
  Record.call(this, parser);

  this.type = 'alert';
  this.level = constants.alertLevel[level];
  this.description = constants.alertDescription[description];
}
util.inherits(Alert, Record);

Parser.prototype.parseAlert = function parseAlert() {
  var err = null;

  if (this.body.size === 2)
    this.push(new Alert(this, this.body.readUInt8(), this.body.readUInt8()));
  else
    err = new Error('Incorrect alert body length: ' + this.body.size);

  return err;
};

function Handshake(parser, type) {
  Record.call(this, parser);

  this.type = 'handshake';
  this.handshakeType = type;
}
util.inherits(Alert, Handshake);

Parser.prototype.parseHandshake = function parseHandshake() {
  var err = null;
  var body;

  if (this.handshakeBuffer) {
    body = this.handshakeBuffer;

    var chunks = this.body.toChunks();
    for (var i = 0; i < chunks.length; i++)
      body.push(chunks[i]);
  } else {
    body = this.body;
  }

  if (!body.has(4)) {
    this.handshakeBuffer = body.clone(body.size);
    return;
  }

  var original = body.clone(body.size);

  var type = constants.handshakeType[body.readUInt8()];
  var length = body.readUInt24BE();

  if (!body.has(length)) {
    this.handshakeBuffer = original;
    return;
  }

  if (this.handshakeBuffer !== null) {
    this.body = this.handshakeBuffer;
    this.rawBody = this.body.clone(this.body.size);
  }

  if (type === 'hello_request' || type === 'server_hello_done')
    err = this.parseGenericHandshake(type, length);
  else if (type === 'client_hello' || type === 'server_hello')
    err = this.parseHello(type, length);
  else if (type === 'finished')
    err = this.parseFinished(type, length);
  else if (type === 'certificate')
    err = this.parseCertificate(type, length);
  else if (type === 'certificate_request')
    err = this.parseCertificateReq(type, length);
  else if (type === 'next_protocol')
    err = this.parseNextProtocol(type, length);
  else if (type === 'client_key_exchange')
    err = this.parseKeyExchange(type, length);
  else if (type === 'server_key_exchange')
    err = this.parseKeyExchange(type, length);
  else if (type === 'session_ticket')
    err = this.parseSessionTicket(type, length);
  else
    err = new Error('Unsupported handshake type: ' + type);

  // Clean-up
  if (this.handshakeBuffer !== null && this.handshakeBuffer.size === 0)
    this.handshakeBuffer = null;

  return err;
};

Parser.prototype.parseGenericHandshake =
    function parseGenericHandshake(type, length) {
  var err = null;

  if (length === 0)
    this.push(new Handshake(this, type));
  else
    err = new Error('Incorrect hello_request length: ' + length);

  return err;
};

function Hello(parser, type, opts) {
  Handshake.call(this, parser, type);

  this.helloVersion = opts.helloVersion;
  this.random = opts.random;
  this.session = opts.session;
  this.cipherSuites = opts.cipherSuites;
  this.cipherSuite = opts.cipherSuite;
  this.compressionMethods = opts.compMethods;
  this.compressionMethod = opts.compMethod;
  this.extensions = {};
  opts.extensions.forEach(function(ext) {
    this.extensions[ext.type] = ext.body;
  }, this);
}
util.inherits(Hello, Handshake);

Parser.prototype.parseHello = function parseHello(type, length) {
  var offset;

  // client version, random, session_id size
  offset = 2 + 32 + 1;
  if (length < offset)
    return new Error('ClientHello OOB');

  var helloVersion = this.body.readUInt16BE();
  var random = this.body.take(32);

  // Read session
  var sessionIdLen = this.body.readUInt8();
  if (length < offset + sessionIdLen)
    return new Error('SessionID OOB');

  var session = this.body.take(sessionIdLen);
  if (session.length === 0)
    session = false;
  offset += sessionIdLen;

  var cipherSuite = null;
  var cipherSuites = null;

  // Read cipher suite
  if (type === 'client_hello') {
    var cipherLen = this.body.readUInt16BE();
    offset += 2;
    if (length < offset + cipherLen + 1)
      return new Error('Cipher Suites OOB');

    offset += cipherLen;

    cipherSuites = [];
    for (var i = 0; i < cipherLen; i += 2) {
      var suite = this.body.readUInt16BE();
      var cipher = constants.cipherSuite[suite];
      if (!cipher)
        continue;
      cipherSuites.push(cipher);
    }

  // Server cipher suite
  } else {
    if (length < offset + 3)
      return new Error('Cipher Suite OOB');

    cipherSuite = constants.cipherSuite[this.body.readUInt16BE()];
    offset += 2;
  }

  // Read compression methods
  var compMethod = null;
  var compMethods = null;

  if (type === 'client_hello') {
    var compLen = this.body.readUInt8();
    offset += 1;
    if (length < offset + compLen)
      return new Error('Compression methods OOB');

    compMethods = [];
    for (var i = 0; i < compLen; i++) {
      var comp = constants.compressionMethod[this.body.readUInt8()];
      compMethods.push(comp);
    }
    offset += compLen;

  // Server compression methods
  } else {
    compMethod = constants.compressionMethod[this.body.readUInt8()];
    offset += 1;
  }

  // Read extensions
  var extensions = [];
  if (length > offset) {
    var extlen = this.body.readUInt16BE();
    offset += 2;
    var extend = offset + extlen;
    if (length < extend)
      return new Error('Extensions list OOB');

    while (offset < extend) {
      offset = this.readExtension(this.body, type, offset, extend, extensions);
      if (typeof offset !== 'number')
        return offset;
    }
  }

  this.push(new Hello(this, type, {
    helloVersion: helloVersion,
    random: random,
    session: session,
    cipherSuites: cipherSuites,
    cipherSuite: cipherSuite,
    compMethods: compMethods,
    compMethod: compMethod,
    extensions: extensions
  }));

  return null;
};

function Certificate(parser, type, certs) {
  Handshake.call(this, parser, type);

  this.certs = certs;
}
util.inherits(Certificate, Handshake);

Parser.prototype.parseCertificate = function parseCertificate(type, length) {
  if (length < 3)
    return new Error('Certificate record is too small');

  var total = this.body.readUInt24BE();
  var offset = 3;

  if (total + offset > length)
    return new Error('Certificate OOB');

  var certs = [];
  total += offset;
  while (offset < total) {
    if (offset + 3 > total)
      return new Error('Certificate is too small');

    var size = this.body.readUInt24BE();
    offset += 3;
    if (offset + size > total)
      return new Error('Certificate OOB');

    certs.push(this.body.take(size));
    offset += size;
  }

  this.push(new Certificate(this, type, certs));

  return null;
};

function CertificateRequest(parser, type, types, algorithms, authorities) {
  Handshake.call(this, parser, type);

  this.types = types;
  this.signatureAlgorithms = algorithms;
  this.authorities = authorities;
}
util.inherits(Certificate, Handshake);

Parser.prototype.parseCertificateReq = function parseCertificateReq(type,
                                                                    length) {
  if (length < 5)
    return new Error('Certificate request record is too small');

  // Parse certificate types
  var typeSize = this.body.readUInt8();
  var offset = 1;

  if (typeSize + offset + 2 > length)
    return new Error('Certificate request types OOB');

  var types = [];
  for (var i = 0; i < typeSize; i++, offset++)
    types.push(constants.clientCertType[this.body.readUInt8()]);

  // Parse algorithms
  var algSize = this.body.readUInt16BE();
  offset += 2;
  if (algSize + offset + 2 > length)
    return new Error('Certificate request algorithms OOB');

  var algorithms = [];
  for (var i = 0; i < algSize; i += 2, offset += 2) {
    algorithms.push({
      hash: constants.hashAlgorithm[this.body.readUInt8()],
      sign: constants.signatureAlgorithm[this.body.readUInt8()]
    });
  }

  // Parse authorities
  var authSize = this.body.readUInt16BE();
  offset += 2;
  if (authSize + offset > length)
    return new Error('Certificate request authorities OOB');

  var authorities = [];
  var end = offset + authSize;
  while (offset < end) {
    var nameSize = this.body.readUInt16BE();
    offset += 2;
    if (nameSize + offset > end)
      return new Error('Certificate request authority name OOB');

    var name = this.body.take(nameSize);
    authorities.push(name);
    offset += nameSize;
  }

  this.push(new CertificateRequest(
    this,
    type,
    types,
    algorithms,
    authorities
  ));

  return null;
};

function Finished(parser, type, verify) {
  Handshake.call(this, parser, type);

  this.verify = verify;
}
util.inherits(Finished, Handshake);

Parser.prototype.parseFinished = function parseFinished(type, length) {
  if (length == 0)
    return new Error('Finished is too small');

  this.push(new Finished(this, type, this.body.take(length)));

  return null;
};

Parser.prototype.readExtension = function readExtension(buff,
                                                        helloType,
                                                        off,
                                                        len,
                                                        list) {
  if (off + 4 > len)
    return new Error('Extension body is too small');

  var type = constants.extensionType[buff.readUInt16BE()],
      extlen = buff.readUInt16BE();

  off += 4;
  if (off + extlen > len)
    return new Error('Extension body OOB');

  var body = buff.clone(extlen);
  buff.skip(extlen);
  off += extlen;

  var extBody;
  if (type === 'server_name')
    extBody = this.parseServerName(helloType, body);
  else if (type === 'signature_algorithms')
    extBody = this.parseSignatureAlgorithms(body);
  else if (type === 'heartbeat')
    extBody = this.parseHearbeatExt(body);
  else
    extBody = body;

  if (extBody instanceof Error)
    return extBody;

  list.push({ type: type, body: extBody });

  return off;
};

Parser.prototype.parseServerName = function parseServerName(type, body) {
  if (type === 'server_hello') {
    if (body.size !== 0)
      return new Error('Extension: server_name is too long');
    return true;
  }

  if (!body.has(2))
    return new Error('Extension: server_name is too short');

  var serverNameCnt = body.readUInt16BE();
  if (!body.has(serverNameCnt))
    return new Error('Extension: ServerNameList OOB');

  var offset = 2,
      end = offset + serverNameCnt,
      names = [];

  while (offset < end) {
    var nameType = body.readUInt8();
    if (nameType !== 0)
      return new Error('Extension: Unknown NameType');

    offset++;
    if (offset + 2 > end)
      return new Error('Extension: Hostname Length OOB');

    var hostnameLen = body.readUInt16BE();
    if (offset + hostnameLen + 2 > end)
      return new Error('Extension: Hostname OOB');
    offset += 2;

    names.push(body.take(hostnameLen).toString());
    offset += hostnameLen;
  }

  return names;
};

Parser.prototype.parseSignatureAlgorithms =
    function parseSignatureAlgorithms(body) {
  if (!body.has(2))
    return new Error('Extension: signature_algorithms is too small');
  var size = body.readUInt16BE();
  if (!body.has(size))
    return new Error('Extension: signature_algorithms OOB');

  var algorithms = [],
      offset = 2,
      end = offset + size;

  while (offset < end) {
    if (offset + 2 > end)
      return new Error('Extension: signature_algorithms is too small');
    var hash = constants.hashAlgorithm[body.readUInt8()];
    var signature = constants.signatureAlgorithm[body.readUInt8()];

    if (!hash || !signature)
      return new Error('Extension: unknown hash or signature');

    algorithms.push({
      hash: hash,
      signature: signature
    });
    offset += 2;
  }

  return algorithms;
};

function NextProtocol(parser, type, selectedProto) {
  Handshake.call(this, parser, type);
  this.selectedProto = selectedProto;
}
util.inherits(NextProtocol, Handshake);

Parser.prototype.parseNextProtocol = function parseNextProtocol(type, length) {
  if (length < 1)
    return new Error('NextProtocol is too small');

  var selectedLen = this.body.readUInt8();
  if (length < 1 + selectedLen)
    return new Error('NextProtocol OOB');

  var selected = this.body.take(selectedLen);

  this.push(new NextProtocol(this, type, selected));

  return null;
};

function KeyExchange(parser, type, content) {
  Handshake.call(this, parser, type);
  this.content = content;
}
util.inherits(KeyExchange, Handshake);

Parser.prototype.parseKeyExchange = function parseKeyExchange(type, length) {
  this.push(new KeyExchange(this, type, this.body));

  return null;
};

function SessionTicket(parser, type, content) {
  Handshake.call(this, parser, type);
  this.content = content;
}
util.inherits(SessionTicket, Handshake);

Parser.prototype.parseSessionTicket =
    function parseSessionTicket(type, length) {
  this.push(new SessionTicket(this, type, this.body));

  return null;
};

function ChangeCipherSpec(parser) {
  Record.call(this, parser);
  this.type = 'change_cipher_spec';
}
util.inherits(ChangeCipherSpec, Record);

Parser.prototype.parseChangeCipherSpec = function parserChangeCipherSpec() {
  var err = null;

  if (this.body.size === 1 && this.body.readUInt8() === 1)
    this.push(new ChangeCipherSpec(this));
  else
    err = new Error('Incorrect ChangeCipherSpec body');

  this.state.switchToPending('read');

  return err;
};

function Heartbeat(parser, type) {
  Record.call(this, parser);
  this.type = 'handshake';
  this.heartbeatType = costants.heartbeatType[type];
};
util.inherits(Heartbeat, Record);

Parser.prototype.parseHeartbeat = function parseHeartbeat() {
  var err = null;

  if (this.body.size === 1 && constants.heartbeatType[this.body.readUInt8()])
    this.push(new Heartbeat(this, this.body[0]));
  else
    err = new Error('Incorrect Heartbeat body');

  return err;
};

Parser.prototype.parseHearbeatExt = function parseHearbeatExt(body) {
  if (!body.has(1))
    return new Error('Extension: heartbeat is too small');

  var mode = constants.heartbeatMode[body.readUInt8()];
  if (!mode)
    return new Error('Extension: incorrect heartbeat mode');

  return mode;
};

//
// Just a helpers for State
//

Parser.prototype._error = function _error(str) {
  var err = str instanceof Error ? str : new Error(str);
  if (!err.description)
    err.description = 'decode_error';
  this.emit('error', err);
  return false;
};

Parser.prototype.parseRSAKeyEx = function parseRSAKeyEx(frame) {
  if (frame.content.size < 2)
    return this._error('Invalid RSA keyEx length');

  var len = frame.content.readUInt16BE();
  if (frame.content.size !== len)
    return this._error('Invalid RSA keyEx length field');

  return frame.content.take(len);
};

Parser.prototype.parseECParams = function parseECParams(body) {
  if (!body.has(3))
    return this._error('Invalid ECDHE keyEx length');

  var type = constants.curveType[body.readUInt8()];
  if (type !== 'named_curve')
    return this._error('Unsupported ECDHE curve type: ' + type);

  var id = body.readUInt16BE();
  var namedCurve = constants.namedCurve[id];
  if (!namedCurve)
    return this._error('Unsupported ECDHE curve: ' + id);

  return {
    type: type,
    value: namedCurve
  };
};

Parser.prototype.parseSignature = function parseSignature(data) {
  if (this.state.version >= 0x0303) {
    if (!data.has(4))
      return this._error('Too small for a Signature');

    var hash = constants.hashAlgorithm[data.readUInt8()];
    var sign = constants.signatureAlgorithm[data.readUInt8()];
    if (!hash || !sign)
      return this._error('Unknown hash or signature algorithm');

    var len = data.readUInt16BE();
    if (!data.has(len))
      return this._error('Signature content length OOB');
    var content = data.take(len);
  } else {
    // TLS < 1.2 doesn't have sig/alg fields
    var hash = 'md5-sha1';
    var sign = this.state.pending.info.auth;

    if (!data.has(2))
      return this._error('Too small for a Signature');

    var len = data.readUInt16BE();
    if (!data.has(len))
      return this._error('Signature content length OOB');
    var content = data.take(len);
  }

  return {
    hash: hash,
    signature: sign,
    content: content
  };
};

Parser.prototype.parseECDHEKeyEx = function parseECDHEKeyEx(frame) {
  var buf = frame.content.clone(frame.content.size);

  var params = this.parseECParams(buf);
  if (!params)
    return false;

  if (!buf.has(1))
    return this._error('EC Point length is too small');

  var pointLen = buf.readUInt8();
  if (!buf.has(pointLen))
    return this._error('EC Point length OOB');

  var point = buf.take(pointLen);

  var signature = this.parseSignature(buf);
  if (!signature)
    return false;

  return {
    params: params,
    rawParams: frame.content,
    point: point,
    signature: signature
  };
};

Parser.prototype.parseECDHEClientKeyEx = function parseECDHEClientKeyEx(frame) {
  if (!frame.content.has(1))
    return this._error('Client ECDHE keyEx is too small');

  var len = frame.content.readUInt8();
  if (!frame.content.has(len))
    return this._error('Client ECDHE keyEx length OOB');

  return frame.content.take(len);
};
