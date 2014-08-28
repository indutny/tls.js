var tls = require('../');
var fs = require('fs');
var net = require('net');
var http = require('http');

var hServer = http.createServer(function(req, res) {
  res.end('Hello world!');
});

var provider = tls.provider.node.create();
var context = tls.context.create({ provider: provider });

context.addKeyPair('rsa', {
  key: fs.readFileSync(__dirname + '/../test/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/../test/keys/cert.pem')
});

net.createServer(function(c) {
  var t = tls.socket.create(c, context, 'server');
  hServer.emit('connection', t);
}).listen(1443, function() {
  console.log('Listening on [%s]:%d',
              this.address().address,
              this.address().port);
});
