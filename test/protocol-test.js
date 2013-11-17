var tls = require('..'),
    net = require('net'),
    assert = require('assert');

var PORT = 8000;

describe('tls.js/Protocol', function() {
  var server;
  var client;
  var serverSide;
  var clientSide;

  beforeEach(function(done) {
    var waiting = 2;
    function wait() {
      if (--waiting === 0) done();
    }
    server = net.createServer(function(socket) {
      serverSide = tls.protocol.create(socket, { type: 'server' });
      serverSide.start();
      wait();
    }).listen(PORT, function() {
      client = net.connect(PORT, function() {
        clientSide = tls.protocol.create(client, { type: 'client' });
        clientSide.start();
        wait();
      });
    });
  });

  it('should establish secure connection', function(done) {
    var waiting = 2;
    function wait() {
      if (--waiting === 0) done();
    }
    serverSide.on('secure', wait);
    clientSide.on('secure', wait);
  });
});
