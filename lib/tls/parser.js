var tls = require('../tls');
var stream = require('stream');
var util = require('util');

var constants = tls.constants;

function Parser(state) {
  stream.Transform.call(this);
  this._readableState.objectMode = true;

  this.state = state;

  this.buffer = null;
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
  // Concat buffers
  if (this.buffer)
    this.buffer = Buffer.concat([ this.buffer, data ]);
  else
    this.buffer = data;

  var err = null;
  while (true) {
    var buffer = this.buffer;

    // If we have enough bytes to feast
    if (!this.header) {
      if (buffer.length < 5)
        break;

      this.header = {
        buffer: buffer.slice(0, 5),
        type: constants.recordType[buffer[0]],
        version: { major: buffer[1], minor: buffer[2] },
        length: buffer.readUInt16BE(3, true)
      };
      // Slice-off header
      buffer = this.buffer = buffer.slice(5);

      // Record length must not exceed 2^14 + 2048
      // NOTE: additional 2048 might be introduced in TLSCipherText
      if (this.header.length > 18432) {
        err = new Error('Invalid record length');
        this.header = null;
      }
    }

    // NOTE: header may be set in previous if clause
    if (this.header) {
      if (buffer.length < this.header.length)
        break;

      this.body = buffer.slice(0, this.header.length);
      this.buffer = buffer.slice(this.header.length);
      this.rawBody = this.body;

      // TODO(indutny): use encryption and compression from state
      err = this.parseBody();

      this.header = false;
      this.body = false;
    }
    if (err)
      break;
  }

  callback(err);
};

Parser.prototype.parseBody = function parseBody() {
  var err;

  if (this.header.type === 'application_data')
    err = this.parseApplicationData();
  if (this.header.type === 'alert')
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
  this.buffers = [ parser.header.buffer, parser.rawBody ];
}

function ApplicationData(parser, body) {
  Record.call(this, parser);
  this.type = 'data';
  this.data = body;
}
util.inherits(ApplicationData, Record);

Parser.prototype.parseApplicationData = function parseApplicationData() {
  this.push(new ApplicationData(this, this.body));

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

  if (this.body.length === 2)
    this.push(new Alert(this, this.body[0], this.body[1]));
  else
    err = new Error('Incorrect alert body length: ' + this.body.length);

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

  if (this.body.length >= 4) {
    var type = constants.handshakeType[this.body[0]];
    var length = this.body.readUInt32BE(0, true) & 0xffffff;

    this.body = this.body.slice(4);
    if (length > this.body.length)
      err = new Error('Handshake length OOB');
    else if (type === 'hello_request' || type === 'server_hello_done')
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
    else
      err = new Error('Unsupported handshake type: ' + type);
  } else
    err = new Error('Incorrect handshake body length: ' + this.body.length);

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

  var helloVersion = { major: this.body[0], minor: this.body[1] };
  var random = {
    time: this.body.readUInt32BE(2, true),
    raw: this.body.slice(2, 34),
    bytes: this.body.slice(6, 34)
  };

  // Read session
  var sessionIdLen = this.body[34];
  if (length < offset + sessionIdLen)
    return new Error('SessionID OOB');

  var session = this.body.slice(offset, offset + sessionIdLen);
  if (session.length === 0)
    session = false;
  offset += sessionIdLen;

  var cipherSuite = null;
  var cipherSuites = null;

  // Read cipher suite
  if (type === 'client_hello') {
    var cipherLen = this.body.readUInt16BE(offset, true);
    offset += 2;
    if (length < offset + cipherLen + 1)
      return new Error('Cipher Suites OOB');

    var rawCipherSuite = this.body.slice(offset, offset + cipherLen);
    offset += cipherLen;

    cipherSuites = [];
    for (var i = 0; i < rawCipherSuite.length; i+= 2) {
      var cipher = constants.cipherSuite[rawCipherSuite.readUInt16BE(i, true)];
      if (!cipher)
        continue;
      cipherSuites.push(cipher);
    }
  } else {
    if (length < offset + 3)
      return new Error('Cipher Suite OOB');

    cipherSuite = constants.cipherSuite[this.body.readUInt16BE(offset, true)];
    offset += 2;
  }

  // Read compression methods
  var compMethod = null;
  var compMethods = null;

  if (type === 'client_hello') {
    var compLen = this.body[offset];
    offset += 1;
    if (length < offset + compLen)
      return new Error('Compression methods OOB');

    compMethods = [];
    var rawCompMethods = this.body.slice(offset, offset + compLen);
    for (var i = 0; i < rawCompMethods.length; i++) {
      var comp = constants.compressionMethod[rawCompMethods[i]];
      compMethods.push(comp);
    }
    offset += compLen;
  } else {
    // Server Hello
    compMethod = constants.compressionMethod[this.body[offset]];
    offset += 1;
  }

  // Read extensions
  var extensions = [];
  if (length > offset) {
    var extlen = this.body.readUInt16BE(offset, true);
    offset += 2;
    var extend = offset + extlen;
    if (length < extend)
      return new Error('Extensions list OOB');

    while (offset < extend) {
      offset = this.readExtension(this.body, offset, extend, extensions);
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

  var total = (this.body[0] << 8) | this.body.readUInt16BE(1, true);
  var offset = 3;

  if (total + offset > length)
    return new Error('Certificate OOB');

  var certs = [];
  total += offset;
  while (offset < total) {
    if (offset + 3 > total)
      return new Error('Certificate is too small');

    var size = (this.body[offset] << 8) |
               this.body.readUInt16BE(offset + 1, true);
    offset += 3;
    if (offset + size > total)
      return new Error('Certificate OOB');

    certs.push(this.body.slice(offset, offset + size));
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
  var typeSize = this.body[0];
  var offset = 1;

  if (typeSize + offset + 2 > length)
    return new Error('Certificate request types OOB');

  var types = [];
  for (var i = 0; i < typeSize; i++, offset++)
    types.push(constants.clientCertType[this.body[offset]]);

  // Parse algorithms
  var algSize = this.body.readUInt16BE(offset, true);
  offset += 2;
  if (algSize + offset + 2 > length)
    return new Error('Certificate request algorithms OOB');

  var algorithms = [];
  for (var i = 0; i < algSize; i += 2, offset += 2) {
    algorithms.push({
      hash: constants.hashAlgorithm[this.body[offset]],
      sign: constants.signatureAlgorithm[this.body[offset + 1]]
    });
  }

  // Parse authorities
  var authSize = this.body.readUInt16BE(offset, true);
  offset += 2;
  if (authSize + offset > length)
    return new Error('Certificate request authorities OOB');

  var authorities = [];
  var end = offset + authSize;
  while (offset < end) {
    var nameSize = this.body.readUInt16BE(offset, true);
    offset += 2;
    if (nameSize + offset > end)
      return new Error('Certificate request authority name OOB');

    var name = this.body.slice(offset, offset + nameSize);
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

  this.push(new Finished(this, type, this.body));

  return null;
};

Parser.prototype.readExtension = function readExtension(buff, off, len, list) {
  if (off + 4 > len)
    return new Error('Extension body is too small');

  var type = constants.extensionType[buff.readUInt16BE(off, true)],
      extlen = buff.readUInt16BE(off + 2, true);

  off += 4;
  if (off + extlen > len)
    return new Error('Extension body OOB');

  var body = buff.slice(off, off + extlen);
  off += extlen;

  var extBody;
  if (type === 'server_name')
    extBody = this.parseServerName(body);
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

Parser.prototype.parseServerName = function parseServerName(body) {
  if (body.length < 2)
    return new Error('Extension: server_name is too short');

  var serverNameCnt = body.readUInt16BE(0, true);
  if (body.length < 2 + serverNameCnt)
    return new Error('Extension: ServerNameList OOB');

  var offset = 2,
      end = offset + serverNameCnt,
      names = [];

  while (offset < end) {
    if (body[offset] !== 0)
      return new Error('Extension: Unknown NameType');

    offset++;
    if (offset + 2 > end)
      return new Error('Extension: Hostname Length OOB');

    var hostnameLen = body.readUInt16BE(offset, true);
    if (offset + hostnameLen + 2 > end)
      return new Error('Extension: Hostname OOB');
    offset += 2;

    names.push(body.slice(offset, offset + hostnameLen).toString());
    offset += hostnameLen;
  }

  return names;
};

Parser.prototype.parseSignatureAlgorithms =
    function parseSignatureAlgorithms(body) {
  if (body.length < 2)
    return new Error('Extension: signature_algorithms is too small');
  var size = body.readUInt16BE(0, true);
  if (size + 2 > body.length)
    return new Error('Extension: signature_algorithms OOB');

  var algorithms = [],
      offset = 2,
      end = offset + size;

  while (offset < end) {
    if (offset + 2 > end)
      return new Error('Extension: signature_algorithms is too small');
    var hash = constants.hashAlgorithm[body[offset]];
    var signature = constants.signatureAlgorithm[body[offset + 1]];

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

  var selectedLen = this.body[0];
  if (length < 1 + selectedLen)
    return new Error('NextProtocol OOB');

  var selected = this.body.slice(1, 1 + selectedLen);

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

function ChangeCipherSpec(parser) {
  Record.call(this, parser);
  this.type = 'change_cipher_spec';
}
util.inherits(ChangeCipherSpec, Record);

Parser.prototype.parseChangeCipherSpec = function parserChangeCipherSpec() {
  var err = null;

  if (this.body.length === 1 && this.body[0] === 1)
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

  if (this.body.length === 1 && constants.heartbeatType[this.body[0]])
    this.push(new Heartbeat(this, this.body[0]));
  else
    err = new Error('Incorrect Heartbeat body');

  return err;
};

Parser.prototype.parseHearbeatExt = function parseHearbeatExt(body) {
  if (body.length < 1)
    return new Error('Extension: heartbeat is too small');

  var mode = contants.heartbeatMode[body[0]];
  if (!mode)
    return new Error('Extension: incorrect heartbeat mode');

  return mode;
};
