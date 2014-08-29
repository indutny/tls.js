var tls = require('../');
var fs = require('fs');

var server = tls.createHTTPServer({
  key: fs.readFileSync(__dirname + '/../test/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/../test/keys/cert.pem'),
  ciphers: [
    'TLS_RSA_WITH_AES_256_CBC_SHA'
  ],
}, function(req, res) {
  res.end('Hello world!');
}).listen(1443, function() {
  console.log('Listening on [%s]:%d',
              this.address().address,
              this.address().port);
});
