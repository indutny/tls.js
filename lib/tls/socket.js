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

  this.parser.on('error', function(err) {
    // TODO(indutny): figure out errors in parser
    self.state._error(err.description || 'unexpected_message', err);
  });

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

  this.state.once('secure', function() {
    self.emit('secure');
    self.parser.removeListener('readable', onParserReadable);
  });
};

Socket.prototype._read = function read(size) {
  while (true) {
    var frame = this.parser.read();
    if (frame === null)
      break;

    var handled = this.state.handle(frame);

    if (!handled) {
      this.state._error('unexpected_message',
                        'Unexpected frame: ' + frame.type);
      break;
    }

    // Let caller know that we are done reading
    this.push('');
  }
};

Socket.prototype._write = function write(data, enc, callback) {
};

Socket.prototype.destroySoon = function destroySoon() {
  this.socket.destroSoon();
};
