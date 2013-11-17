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
  this.pendingState = this.state.clone();

  this.type = this.state.type;
  this.framer = tls.framer.create(state);
  this.parser = tls.parser.create(state);

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

  this.framer.on('random', function(bytes) {
    self.state.setRandom(bytes);
  });
};

Protocol.prototype.start = function start() {
  var self = this;

  if (this.type === 'client') {
    // Send ClientHello
    this.framer.hello('client', {
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

Protocol.prototype._read = function read(size) {
  var frame = this.parser.read();
  if (frame === null)
    return;

};

Protocol.prototype._write = function write(frame, enc, callback) {
};
