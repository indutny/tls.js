var tls = require('../tls');
var stream = require('stream');
var util = require('util');

var constants = tls.constants;

function Parser() {
  stream.Transform.call(this);
  this._readableState.objectMode = true;

  this.buffer = null;
  this.header = false;
  this.body = false;
}
util.inherits(Parser, stream.Transform);
module.exports = Parser;

Parser.create = function create() {
  return new Parser();
};

Parser.prototype._transform = function transform(data, encoding, callback) {
  // Concat buffers
  if (this.buffer)
    this.buffer = Buffer.concat([ this.buffer, data ]);
  else
    this.buffer = data;

  var buffer = this.buffer,
      err = null;

  // If we have enough bytes to feast
  if (!this.header) {
    if (buffer.length >= 5) {
      this.header = {
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
  }
  if (this.header && buffer.length >= this.header.length) {
    this.body = buffer.slice(0, this.header.length);
    this.buffer = buffer.slice(this.header.length);

    if (this.header.type === 'application_data')
      err = this.parseApplicationData();
    if (this.header.type === 'alert')
      err = this.parseAlert();
    else if (this.header.type === 'handshake')
      err = this.parseHandshake();
    else if (this.header.type === 'change_cipher_spec')
      err = this.parseChangeCipherSpec();
    else
      err = new Error(this.header.type + ' is not supported yet');

    this.header = false;
    this.body = false;
  }

  callback(err);
};

function Record(header) {
  this.version = header.version;
}

function ApplicationData(header, body) {
  Record.call(this, header);
  this.type = 'data';
  this.data = body;
}
util.inherits(ApplicationData, Record);

Parser.prototype.parseApplicationData = function parseApplicationData() {
  this.push(new ApplicationData(this.header, this.body));

  return null;
};

function Alert(header, level, description) {
  Record.call(this, header);

  this.type = 'alert';
  this.version = header.version;
  this.level = constants.alertLevel[level];
  this.description = constants.alertDescription[description];
}
util.inherits(Alert, Record);

Parser.prototype.parseAlert = function parseAlert() {
  var err = null;

  if (this.body.length === 2)
    this.push(new Alert(this.body[0], this.body[1]));
  else
    err = new Error('Incorrect alert body length: ' + this.body.length);

  return err;
};

function Handshake(header, type) {
  Record.call(this, header);

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
    else if (type === 'certificate')
      err = this.parseCertificate(type, length);
    else if (type === 'next_protocol')
      err = this.parseNextProtocol(type, length);
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
    this.push(new Handshake(this.header, type));
  else
    err = new Error('Incorrect hello_request length: ' + length);

  return err;
};

function Hello(header, type, opts) {
  Handshake.call(this, header, type);

  this.helloVersion = opts.helloVersion;
  this.random = opts.random;
  this.session = opts.session;
  this.cipherSite = opts.cipherSuite;
  this.compMethods = opts.compMethods;
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
  offset += sessionIdLen;

  // Read cipher suite
  var cipherLen = this.body.readUInt16BE(offset, true);
  offset += 2;
  if (length < offset + cipherLen + 1)
    return new Error('Cipher Suite OOB');

  var rawCipherSuite = this.body.slice(offset, offset + cipherLen);
  offset += cipherLen;

  var cipherSuite = [];
  for (var i = 0; i < rawCipherSuite.length; i+= 2) {
    var cipher = constants.cipherSuite[rawCipherSuite.readUInt16BE(i, true)];
    if (!cipher)
      continue;
    cipherSuite.push(cipher);
  }

  // Read compression methods
  var compLen = this.body[offset];
  offset += 1;
  if (length < offset + compLen)
    return new Error('Compression methods OOB');

  var compMethods = this.body.slice(offset, offset + compLen);
  offset += compLen;

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

  this.push(new Hello(this.header, type, {
    helloVersion: helloVersion,
    random: random,
    session: session,
    cipherSuite: cipherSuite,
    compMethods: compMethods,
    extensions: extensions
  }));

  return null;
};

function Certificate(header, type, certs) {
  Handshake.call(this, header, type);

  this.certs = certs;
}
util.inherits(Certificate, Handshake);

Parser.prototype.parseCertificate = function parseCertificate(type, length) {
  if (length < 3)
    return new Error('Certificate is too small');

  var total = (this.body[0] << 8) | this.body.readUInt16BE(1, true);
  var offset = 3;

  if (total + offset > length)
    return new Error('Ceritifcate OOB');

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

  this.push(new Certificate(this.header, type, certs));

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

function NextProtocol(header, type, selectedProto) {
  Handshake.call(this, header, type);
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

  this.push(new NextProtocol(this.header, type, selected));

  return null;
};

function ChangeCipherSpec(header) {
  Record.call(this, header);
  this.type = 'change_cipher_spec';
}
util.inherits(ChangeCipherSpec, Record);

Parser.prototype.parseChangeCipherSpec = function parserChangeCipherSpec() {
  if (this.body.length < 1 || this.body[0] !== 1)
    return new Error('Incorrect ChangeCipherSpec body');

  this.push(new ChangeCipherSpec(this.header));

  return null;
};
