var tls = require('../tls');
var util = require('util');
var stream = require('stream');

var constants = tls.constants;

function Socket(socket, context, type) {
  stream.Duplex.call(this);

  this._tlsState = tls.state.create({
    type: type,
    context: context,
    socket: socket
  });

  this._init();
};
module.exports = Socket;
util.inherits(Socket, stream.Duplex);

Socket.create = function create(socket, context, type) {
  return new Socket(socket, context, type);
};

Socket.prototype._init = function init() {
  var self = this;
  var state = this._tlsState;

  state.socket.pipe(state.parser);
  state.framer.pipe(state.socket);

  state.socket.on('error', function(err) {
    state._error('unexpected_message', err);
  });

  state.on('error', function(err) {
    self.emit('error', err);
    self.destroySoon(err);
  });

  state.socket.once('close', function() {
    state.socket.unpipe(state.parser);
    state.framer.unpipe(state.socket);
  });
};

Socket.prototype.start = function start() {
  var self = this;
  var state = this._tlsState;

  // Send ClientHello
  state.start();

  // Force cycling data until secure
  state.parser.on('readable', onParserReadable);
  function onParserReadable() {
    self.read(0);
  };

  // Send close_notify on EOF
  this.once('end', function() {
    state.framer.alert('warning', 'close_notify');
  });

  state.once('secure', function() {
    self.emit('secure');
    state.parser.removeListener('readable', onParserReadable);
  });
};

Socket.prototype._read = function read(size) {
  var readSize = 0;
  var state = this._tlsState;
  while (true) {
    var frame = state.parser.read();
    if (frame === null)
      break;

    if (state.socket.cork)
      state.socket.cork();

    var handled = state.handle(frame);

    if (state.socket.uncork)
      state.socket.uncork();

    if (!handled) {
      state._error(
        'unexpected_message',
        'Unexpected frame: ' + (frame.handshakeType || frame.type));
      break;
    }

    // Data
    if (frame.type === 'application_data') {
      for (var i = 0; i < frame.chunks.length; i++) {
        readSize += frame.chunks[i].length;
        this.push(frame.chunks[i]);
      }
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
  state.parser.once('readable', function() {
    self._read(size);
  });
};

Socket.prototype._write = function write(data, enc, callback) {
  if (!this._tlsState.secure) {
    var self = this;
    this._tlsState.once('secure', function() {
      self._write(data, enc, callback);
    });
    return;
  }

  this._tlsState.framer.appData(data);
  callback();
};

// Convenience methods

Socket.prototype.destroy = function destroy(err) {
  return this._tlsState.socket.destroy(err);
};

Socket.prototype.destroySoon = function destroySoon(err) {
  return this._tlsState.socket.destroySoon(err);
};

Socket.prototype.setTimeout = function setTimeout(ms, cb) {
  return this._tlsState.socket.setTimeout(ms, cb);
};

Socket.prototype.address = function address() {
  return this._tlsState.socket.address();
};

Object.defineProperties(Socket.prototype, {
  remoteAddress: {
    get: function() {
      return this._tlsState.socket.remoteAddress;
    }
  },
  remotePort: {
    get: function() {
      return this._tlsState.socket.remotePort;
    }
  }
});
