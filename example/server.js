var tls = require('../');
var https = require('https');
var fs = require('fs');
var cluster = require('cluster');

var node = https.createServer({
  key: fs.readFileSync(__dirname + '/../test/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/../test/keys/cert.pem'),
  ciphers: 'AES256-SHA',
}, onRequest);
node.listen(1443, onListen.bind(node, 'node.js'));

var tlsjs = tls.createHTTPServer({
  key: fs.readFileSync(__dirname + '/../test/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/../test/keys/cert.pem'),
  ciphers: [
    'TLS_RSA_WITH_AES_256_CBC_SHA'
  ],
}, onRequest);
tlsjs.listen(1444, onListen.bind(tlsjs, 'tls.js'));

function onRequest(req, res) {
  res.end('Hello world!');
}

function onListen(name) {
  console.log('<%s> listening on [%s]:%d',
              name,
              this.address().address,
              this.address().port);
}
