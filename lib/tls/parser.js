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
};
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
    }
  }
  if (this.header && buffer.length >= this.header.length) {
    this.body = buffer.slice(0, this.header.length);
    this.buffer = buffer.slice(this.header.length);

    if (this.header.type === 'alert')
      err = this.parseAlert();
    else if (this.header.type === 'handshake')
      err = this.parseHandshake();
    else
      err = new Error(this.header.type + ' is not supported yet');

    this.header = false;
    this.body = false;
  }

  callback(err);
};

function Record(header) {
  this.version = header.version;
};

function Alert(header, level, description) {
  Record.call(this, header);

  this.type = 'alert';
  this.version = header.version;
  this.level = constants.alertLevel[level];
  this.description = constants.alertDescription[description];
};
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
};
util.inherits(Alert, Handshake);

Parser.prototype.parseHandshake = function parseHandshake() {
  var err = null;

  if (this.body.length >= 4) {
    var type = constants.handshakeType[this.body[0]];
    var length = this.body.readUInt32BE(0, true) & 0xffffff;

    this.body = this.body.slice(4);
    if (length > this.body.length)
      err = new Error('Handshake length OOB');
    else if (type === 'hello_request')
      err = this.parseHelloRequest(type, length);
    else if (type === 'client_hello')
      err = this.parseClientHello(type, length);
    else if (type === 'next_protocol')
      err = this.parseNextProtocol(type, length);
    else
      err = new Error('Unsupported handshake type: ' + type);
  } else
    err = new Error('Incorrect handshake body length: ' + this.body.length);

  return err;
};

Parser.prototype.parseHelloRequest = function parseHelloRequest(type, length) {
  var err = null;

  if (length === 0)
    this.push(new Handshake(this.header, type));
  else
    err = new Error('Incorrect hello_request length: ' + length);

  return err;
};

function ClientHello(header,
                     type,
                     clientVersion,
                     random,
                     session,
                     cipherSuite,
                     compMethods,
                     extensions) {
  Handshake.call(this, header, type);

  this.clientVersion = clientVersion;
  this.random = random;
  this.session = session;
  this.cipherSuite = cipherSuite;
  this.compMethods = compMethods;
  this.extensions = {};
  extensions.forEach(function(ext) {
    this.extensions[ext.type] = ext.body;
  }, this);
};
util.inherits(ClientHello, Handshake);

Parser.prototype.parseClientHello = function parseClientHello(type, length) {
  var offset;

  // client version, random, session_id size
  offset = 2 + 32 + 1;
  if (length < offset)
    return new Error('ClientHello OOB');

  var clientVersion = { major: this.body[0], minor: this.body[1] };
  var random = {
    time: this.body.readUInt32BE(2, true),
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

  var cipherSuite = this.body.slice(offset, offset + cipherLen);
  offset += cipherLen;

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

  this.push(new ClientHello(this.header,
                            type,
                            clientVersion,
                            random,
                            session,
                            cipherSuite,
                            compMethods,
                            extensions));
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

  var ext;
  if (type === 'server_name')
    ext = this.parseServerName(type, body);
  else
    ext = { type: type, body: body };

  if (ext instanceof Error)
    return ext;

  list.push(ext);

  return off;
};

Parser.prototype.parseServerName = function parseServerName(type, body) {
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

  return {
    type: type,
    body: names
  };
};

function NextProtocol(header, type, selectedProto) {
  Handshake.call(this, header, type);
  this.selectedProto = selectedProto;
};
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
