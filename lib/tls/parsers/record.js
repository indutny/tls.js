var tls = require('../../tls');
var constants = tls.constants;
var util = require('util');

function RecordParser(options) {
  tls.parsers.base.call(this, options);

  this.state = 'header';
  this.current = null;
};
util.inherits(RecordParser, tls.parsers.base);
module.exports = RecordParser;
RecordParser.create = tls.parsers.base.create;

RecordParser.prototype.parse = function parse() {
  var res = false;

  if (this.state === 'header') {
    res = this.parseHeader();
  } else if (this.state === 'raw-body') {
    res = this.parseRawBody();
  } else if (this.state === 'alert-body') {
    res = this.parseAlertBody();
  } else if (this.state === 'handshake-header') {
    res = this.parseHandshakeHeader();
  } else if (this.state === 'clienthello') {
    res = this.parseClientHello();
  } else if (this.state === 'clienthello-sess') {
    res = this.parseClientHelloSess();
  } else if (this.state === 'clienthello-ciphers') {
    res = this.parseClientHelloCiphers();
  } else if (this.state === 'clienthello-comp') {
    res = this.parseClientHelloComp();
  } else if (this.state === 'clienthello-ext') {
    res = this.parseClientHelloExt();
  }

  return res;
};

function Record(type, version, length) {
  this.type = constants.recordType[type];
  this.version = version.toString(16);
  this.length = length;
  this.body = null;
};

RecordParser.prototype.parseHeader = function parseHeader() {
  var res = false;

  if (5 <= this.bufferSize) {
    this.current = new Record(this.readInt(1, 0),
                              this.readInt(2, 1),
                              this.readInt(2, 3));
    this.skip(5);

    if (this.current.type === 'handshake') {
      this.state = 'handshake-header';
    } else if (this.current.type === 'alert') {
      this.state = 'alert-body';
    } else {
      this.state = 'raw-body';
    }
    res = true;
  }

  return res;
};

RecordParser.prototype.parseRawBody = function parseRawBody() {
  var res = false;

  if (this.current.length <= this.bufferSize) {
    this.current.body = this.readBuffer(this.current.length, 0);
    this.skip(this.current.length);

    this.push(this.current);
    this.current = null;

    this.state = 'header';
    res = true;
  }

  return res;
};

function Alert(level, description) {
  this.level = constants.alertLevel[level];
  this.description = constants.alertDescription[description];
};

RecordParser.prototype.parseAlertBody = function parseAlertBody() {
  var res = false;

  if (2 <= this.bufferSize) {
    this.current.body = new Alert(this.readInt(1, 0), this.readInt(1, 1));
    this.skip(2);

    this.push(this.current);
    this.current = null;

    this.state = 'header';
    res = true;
  }

  return res;
};

function Handshake(msg_type, length) {
  this.type = constants.handshakeType[msg_type];
  this.length = length;
  this.handshake = null;
};

RecordParser.prototype.parseHandshakeHeader = function parseHandshakeHeader() {
  var res = false;

  if (4 <= this.bufferSize) {
    this.current.body = new Handshake(this.readInt(1, 0),
                                      (this.readInt(1, 1) << 16) |
                                      this.readInt(2, 2));
    this.skip(4);

    var htype = this.current.body.type;
    if (htype === 'hello_request') {
      // empty body
      this.push(this.current);
      this.current = null;
      this.state = 'header';
    } else if (htype === 'client_hello') {
      this.state = 'clienthello';
    }
    res = true;
  }

  return res;
};

function ClientHello(version, unix_time, random, sessionLen) {
  this.version = version.toString(16);
  this.random = {
    time: unix_time,
    bytes: random
  };
  this.sessionLen = sessionLen;
  this.session = null;
  this.cipherLen = null;
  this.cipherSuite = null;
  this.compressionLen = null;
  this.compressions = [];
  this.extensions = [];
};

RecordParser.prototype.parseClientHello = function parseClientHello() {
  var res = false;

  // version + random + session_id.length
  if (2 + 32 + 1 <= this.bufferSize) {
    this.current.body.handshake = new ClientHello(this.readInt(2, 0),
                                                  this.readInt(4, 2),
                                                  this.readBuffer(28, 6),
                                                  this.readInt(1, 34));
    this.skip(2 + 32 + 1);

    this.state = 'clienthello-sess';
    res = true;
  }

  return res;
};

RecordParser.prototype.parseClientHelloSess = function parseClientHelloSess() {
  var res = false;
  var handshake = this.current.body.handshake;

  // Session + cipherLen
  if (handshake.sessionLen + 2 <= this.bufferSize) {
    handshake.session = this.readBuffer(handshake.sessionLen, 0);
    handshake.cipherLen = this.readInt(2, handshake.sessionLen);
    this.skip(handshake.sessionLen + 2);

    this.state = 'clienthello-ciphers';
    res = true;
  }

  return res;
};

RecordParser.prototype.parseClientHelloCiphers =
    function parseClientHelloCiphers() {
  var res = false;
  var handshake = this.current.body.handshake;

  // Ciphers + compressionLen
  if (handshake.cipherLen + 1 <= this.bufferSize) {
    handshake.cipherSuite = this.readBuffer(handshake.cipherLen, 0);
    handshake.compressionLen = this.readInt(1, handshake.cipherLen);
    this.skip(handshake.cipherLen + 1);

    this.state = 'clienthello-comp';
    res = true;
  }

  return res;
};

RecordParser.prototype.parseClientHelloComp = function parseClientHelloComp() {
  var res = false;
  var handshake = this.current.body.handshake;

  // Compression
  if (handshake.compressionLen <= this.bufferSize) {
    handshake.compressions = this.readBuffer(handshake.compressionLen, 0);
    this.skip(handshake.compressionLen);

    this.state = 'clienthello-ext';
    res = true;
  }

  return res;
};

RecordParser.prototype.parseClientHelloExt = function parseClientHelloExt() {
  var res = false;
  var handshake = this.current.body.handshake;
  var extSize = this.current.length - this.current.body.length;

  // Compression
  if (extSize <= this.bufferSize) {
    handshake.extensions = this.readBuffer(extSize, 0);
    this.skip(extSize);

    this.push(this.current);
    this.current = null;

    this.state = 'header';
    res = true;
  }

  return res;
};
