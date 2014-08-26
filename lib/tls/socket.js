var tls = require('../tls');
var util = require('util');
var stream = require('stream');

var constants = tls.constants;

function Socket(socket, context, type) {
  stream.Duplex.call(this);

  this.socket = socket;

  this.type = type;

  this.state = tls.state.create({
    type: type,
    context: context,
    socket: this.socket
  });
  this.framer = this.state.framer;
  this.parser = this.state.parser;

  this._init();
};
module.exports = Socket;
util.inherits(Socket, stream.Duplex);

Socket.create = function create(socket, context, type) {
  return new Socket(socket, context, type);
};

Socket.prototype._init = function init() {
  var self = this;

  this.socket.pipe(this.parser);
  this.framer.pipe(this.socket);

  this.socket.on('error', function(err) {
    self.state._error('unexpected_message', err);
  });

  this.state.on('error', function(err) {
    // Ignore, the socket is already closed
  });
};

Socket.prototype.start = function start() {
  var self = this;

  if (this.type === 'client') {
    // Send ClientHello
    this.framer.hello('client', {
      session: this.state.pending.id,
      cipherSuites: this.state.getCipherSuites()
    });
  }

  // Force cycling data until secure
  this.parser.on('readable', onParserReadable);
  function onParserReadable() {
    self.read(0);
  };

  // Send close_notify on EOF
  this.once('end', function() {
    this.framer.alert('warning', 'close_notify');
  });

  this.state.once('secure', function() {
    self.emit('secure');
    self.parser.removeListener('readable', onParserReadable);
  });
};

Socket.prototype._read = function read(size) {
  var readSize = 0;
  while (true) {
    var frame = this.parser.read();
    if (frame === null)
      break;

    var handled = this.state.handle(frame);

    if (!handled) {
      this.state._error(
        'unexpected_message',
        'Unexpected frame: ' + (frame.handshakeType || frame.type));
      break;
    }

    // Data
    if (frame.type === 'application_data') {
      readSize += frame.data.length;
      this.push(frame.data);
    }

    // EOF
    if (frame.type === 'alert' && frame.description === 'close_notify') {
      readSize = Infinity;
      this.push(null);
    }
  }

  if (readSize !== 0)
    return;

  // Retry reading, when parser will have data
  var self = this;
  this.parser.once('readable', function() {
    self._read(size);
  });
};

Socket.prototype._write = function write(data, enc, callback) {
  if (!this.state.secure) {
    var self = this;
    this.state.once('secure', function() {
      self._write(data, enc, callback);
    });
    return;
  }

  this.framer.appData(data);
  callback();
};

Socket.prototype.destroySoon = function destroySoon(err) {
  this.socket.destroySoon(err);
};
