var tls = require('..'),
    net = require('net'),
    realTls = require('tls'),
    assert = require('assert'),
    EE = require('events').EventEmitter;

var PORT = 8000;

describe('tls.js/Parser', function() {
  var server = null;
  var ee = null;
  var socket = null;

  before(function(cb) {
    server = net.createServer(function(s) {
      var parser = tls.parsers.record.create();
      s.pipe(parser);

      parser.on('readable', function() {
        var r = parser.read();
        if (r) {
          ee.emit('record', r);
        }
      });
    }).listen(PORT, cb);
  });

  after(function(cb) {
    server.close(cb);
  });

  beforeEach(function() {
    ee = new EE();
  });

  afterEach(function() {
    ee = null;
    if (socket) {
      socket.destroy();
      socket = null;
    }
  });

  it('should parse tls frames', function(cb) {
    socket = realTls.connect(PORT);

    ee.once('record', function(r) {
      assert.equal(r.type, 'handshake');
      assert.ok(r.length > 0);

      var body = r.body;
      assert.ok(body);
      assert.equal(body.type, 'client_hello');

      var handshake = body.handshake;
      assert.ok(handshake);
      assert.ok(handshake.version >= r.version);

      cb();
    });
  });
});
