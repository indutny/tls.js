var tls = require('../tls');
var util = require('util');
var stream = require('stream');

var constants = tls.constants;

function Protocol(socket, state) {
  stream.Duplex.call(this);

  this.socket = socket;
  if (state instanceof tls.state)
    this.state = state;
  else
    this.state = tls.state.create(state);

  this.type = this.state.type;
  this.wait = this.type === 'client' ? 'serverHello' :
                                       'clientHello';
  this.initialWait = this.wait;
  this.framer = tls.framer.create(this.state);
  this.parser = tls.parser.create(this.state);

  this._init();
};
module.exports = Protocol;
util.inherits(Protocol, stream.Duplex);

Protocol.create = function create(socket, state) {
  return new Protocol(socket, state);
};

Protocol.prototype._init = function init() {
  var self = this;

  this.socket.pipe(this.parser);
  this.framer.pipe(this.socket);

  // Start recording messages
  this.state.recordMessages();

  this.parser.on('error', function(err) {
    // TODO(indutny): figure out errors in parser
    self._error(err.description || 'unexpected_message', err);
  });

  this.socket.on('error', function(err) {
    self._error('unexpected_message', err);
  });

  this.framer.on('random', function(bytes) {
    self.state.setRandom(bytes);
  });
};

Protocol.prototype.start = function start() {
  var self = this;

  // Start recording messages (needed if we are renegotiating)
  this.state.recordMessages();

  if (this.type === 'client') {
    // Send ClientHello
    this.framer.hello('client', {
      session: this.state.session.id,
      cipherSuites: this.state.getCipherSuites()
    });
  }

  // Force cycling data until secure
  this.parser.on('readable', onParserReadable);
  function onParserReadable() {
    self.read(0);
  };

  this.once('secure', function() {
    this.parser.removeListener('readable', onParserReadable);
  });
};

Protocol.prototype._error = function error(description, msg) {
  this.framer.alert('fatal', description);
  this.socket.destroy();
  this.emit('error', msg instanceof Error ? msg : new Error(msg));
};

Protocol.prototype._read = function read(size) {
  while (true) {
    var frame = this.parser.read();
    if (frame === null)
      break;

    var handled = false;

    // Alert level protocol
    if (frame.type === 'alert')
      handled = this._handleAlert(frame);
    else if (frame.type === 'handshake')
      handled = this._handleHandshake(frame);
    else if (frame.type === 'change_cipher_spec')
      handled = this._handleChangeCipher(frame);
    else if (frame.type === 'heartbeat')
      handled = this._handleHeartbeat(frame);

    if (!handled) {
      this._error('unexpected_message', 'Unexpected frame: ' + frame.type);
      break;
    }

    // Let caller know that we are done reading
    this.push('');
  }
};

Protocol.prototype._handleAlert = function handleAlert(frame) {
  if (frame.level === 'fatal') {
    this.socket.destroy();
    this.emit('error', new Error('Received alert: ' + frame.description));
    return true;
  }

  // TODO(indutny): Handle not fatal alerts
  return true;
};

Protocol.prototype._handleHandshake = function handleHandshake(frame) {
  // NOTE: We are doing it not in parser, because parser may parse more
  // frames that we have yet observed.
  // Accumulate state for `verifyData` hash
  if (frame.handshakeType !== 'hello_request')
    this.state.addHandshakeMessage(frame.buffers);

  if (this.wait === 'clientHello') {
    if (frame.handshakeType !== 'client_hello')
      return false;

    this.framer.hello('server', {
      cipherSuite: this.state.selectCipherSuite(frame.cipherSuites)
    });
    this.framer.helloDone();
    this.wait = 'clientFinished';
  } else if (this.wait === 'serverHello') {
    if (frame.handshakeType !== 'server_hello')
      return false;

    this.state.selectCipherSuite(frame.cipherSuite);
    this.wait = 'serverHelloDone';
  } else if (this.wait === 'serverHelloDone') {
    if (frame.handshakeType !== 'server_hello_done')
      return false;

    this.framer.changeCipherSpec();
    this.framer.finished(this.state.verifyData());
    this.wait = 'serverFinished';
  } else if (this.wait === 'clientFinished' || this.wait === 'serverFinished') {
    if (frame.handshakeType !== 'finished')
      return false;

    if (this.wait === 'clientFinished') {
      this.framer.changeCipherSpec();
      this.framer.finished(this.state.verifyData());
    }

    // TODO(indutny): check renegotiation support
    this.wait = this.initialWait;
    this.emit('secure');
  } else {
    return false;
  }

  return true;
};

Protocol.prototype._handleChangeCipher = function handleChangeCipher() {
  return this.state.switchToPending();
};

Protocol.prototype._write = function write(frame, enc, callback) {
};
