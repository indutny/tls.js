var utils = exports;

var assert = require('assert');
var Buffer = require('buffer').Buffer;
var util = require('util');
var stream = require('stream');
var OffsetBuffer = require('obuf');

var tls = require('../tls.js');
var constants = tls.constants;

utils.toPEM = function toPEM(type, data) {
  var text = data.toString('base64');
  var out = [ '-----BEGIN ' + type + '-----' ];
  for (var i = 0; i < text.length;)
    out.push(text.slice(i, i += 64));
  out.push('-----END ' + type + '-----');
  return out.join('\n');
};

utils.fromPEM = function fromPEM(data) {
  var text = data.toString().split(/(\r\n|\r|\n)+/g);
  text = text.filter(function(line) {
    return line.trim().length !== 0;
  });
  text = text.slice(1, -1).join('');
  return new Buffer(text.replace(/[^\w\d\+\/=]+/g, ''), 'base64');
};

utils.getLeaf = function getLeaf(crypto, certs) {
  // TODO(indunty): find leaf
  return certs[0];
};

utils.incSeq = function incSeq(buf) {
  for (var i = 7; i >= 0; i--) {
    if (buf[i] < 255) {
      buf[i]++;
      break;
    }
    buf[i] = 0;
  }
};

function NullCipher() {
}
utils.NullCipher = NullCipher;

NullCipher.prototype.write = function write(out, inp) {
  inp.copy(out);
};

function PRF(hmac, secret, label, seed) {
  this.hmac = hmac;

  this.secret = secret;
  this.label = label;
  this.seed = seed;

  // A(i) in RFC5246
  this.a = null;

  // Left overs
  this.buf = new OffsetBuffer();
}
utils.PRF = PRF;

utils.prf = function prf(hmac) {
  return function(secret, label, seed) {
    return new PRF(hmac, secret, label, seed);
  };
};

PRF.prototype.getA = function getA() {
  if (this.a) {
    this.a = this.hmac(this.secret).update(this.a).digest('buffer');
  } else {
    var h = this.hmac(this.secret)
                .update(this.label)
    for (var i = 0; i < this.seed.length; i++)
      h.update(this.seed[i]);
    this.a = h.digest('buffer');
  }
  return this.a;
};

PRF.prototype.read = function read(size) {
  while (!this.buf.has(size)) {
    var h = this.hmac(this.secret).update(this.getA())
                                  .update(this.label);
    for (var i = 0; i < this.seed.length; i++)
      h.update(this.seed[i]);

    this.buf.push(h.digest('buffer'));
  }

  return this.buf.take(size);
};

//
// md5/sha-1 polyfill for ssl3/tls1.0/tls1.1
//
function SSL3Hash(crypto) {
  this.md5 = crypto.hash('md5')();
  this.sha1 = crypto.hash('sha1')();
}

SSL3Hash.prototype.update = function update(buf, enc) {
  this.md5.update(buf, enc);
  this.sha1.update(buf, enc);

  return this;
};

SSL3Hash.prototype.digest = function digest(enc) {
  var res = Buffer.concat([
    this.md5.digest('buffer'),
    this.sha1.digest('buffer')
  ], 36);

  if (enc === 'buffer' || !enc)
    return res;

  return res.toString(enc);
};

utils.ssl3hash = function ssl3hash(crypto) {
  return function() {
    return new SSL3Hash(crypto);
  };
};

function SSL3PRF(crypto, secret, label, seed) {
  // 32 bytes = 256 bits, we should not generate way too much entropy
  stream.Readable.call(this, {
    highWaterMark: 32
  });

  assert.equal(secret.length % 2, 0);

  var lsecret = secret.slice(0, secret.length >> 1);
  var rsecret = secret.slice(lsecret.length);

  this.md5prf = new PRF(crypto.mac('md5'), lsecret, label, seed);
  this.sha1prf = new PRF(crypto.mac('sha1'), rsecret, label, seed);
}
util.inherits(SSL3PRF, stream.Readable);

SSL3PRF.prototype.read = function read(size) {
  var md5 = this.md5prf.read(size);
  var sha1 = this.sha1prf.read(size);
  assert.equal(md5.length, size);
  assert.equal(sha1.length, size);

  var res = new Buffer(size);
  for (var i = 0; i < size; i++)
    res[i] = md5[i] ^ sha1[i];

  return res;
};

utils.ssl3prf = function ssl3prf(crypto) {
  return function(secret, label, seed) {
    return new SSL3PRF(crypto, secret, label, seed);
  };
};

utils.deriveSecrets = function deriveSecrets(info,
                                             prf,
                                             pre,
                                             client,
                                             server) {
  var master = prf(pre, constants.prf.master, [
    client,
    server
  ]).read(constants.masterLength);

  var macSize = info.macSize / 8;
  var keySize = info.bulk.keySize / 8;
  var ivSize = info.bulk.ivSize / 8;

  var rrandoms = [ server, client ];
  var keyBlock = prf(master, constants.prf.key, [
    server,
    client
  ]).read(2 * (macSize + keySize + ivSize));

  var off = 0;
  var clientWriteMacKey = keyBlock.slice(off, off + macSize);
  off += macSize;
  var serverWriteMacKey = keyBlock.slice(off, off + macSize);
  off += macSize;
  var clientWriteKey = keyBlock.slice(off, off + keySize);
  off += keySize;
  var serverWriteKey = keyBlock.slice(off, off + keySize);
  off += keySize;
  var clientWriteIV = keyBlock.slice(off, off + ivSize);
  off += ivSize;
  var serverWriteIV = keyBlock.slice(off, off + ivSize);

  return {
    master: master,
    client: {
      mac: clientWriteMacKey,
      key: clientWriteKey,
      iv: clientWriteIV
    },
    server: {
      mac: serverWriteMacKey,
      key: serverWriteKey,
      iv: serverWriteIV
    }
  };
};
