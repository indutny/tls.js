# TLS.js [![Build Status](https://travis-ci.org/indutny/tls.js.png)](https://travis-ci.org/indutny/tls.js)

TLS protocol implementation in javascript.

## Installation

```javascript
npm install tls.js
```

## Usage

```javascript
var tls = require('tls.js');

tls.createHTTPServer({
  key: fs.readFileSync(__dirname + '/test/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/test/keys/cert.pem'),
  ciphers: [
    'TLS_RSA_WITH_AES_256_CBC_SHA'
  ],
}, function(res, res) {
  res.end('hello world!');
}).listen(1443, function() {
  console.log('Listening!');
});
```

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
