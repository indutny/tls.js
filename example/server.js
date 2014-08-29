var tls = require('../');
var fs = require('fs');
var net = require('net');
var http = require('http');

var hServer = http.createServer(function(req, res) {
  res.end('Hello world!');
});

var provider = tls.provider.node.create();
var context = tls.context.create({ provider: provider });

context.setCiphers([
  'TLS_RSA_WITH_AES_256_CBC_SHA',
  'TLS_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_AES_256_CBC_SHA256',
  'TLS_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_RSA_WITH_DES_CBC_SHA',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  'TLS_RSA_WITH_RC4_128_MD5',
  'TLS_RSA_WITH_RC4_128_SHA',
  'TLS_RSA_WITH_NULL_SHA',
  'TLS_RSA_WITH_IDEA_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
]);

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
