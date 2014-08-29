var utils = exports;

var assert = require('assert');
var Buffer = require('buffer').Buffer;
var util = require('util');
var stream = require('stream');

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
  this.buf = null;
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
    this.a = this.hmac(this.secret)
                 .update(this.label)
                 .update(this.seed)
                 .digest('buffer');
  }
  return this.a;
};

PRF.prototype.read = function read(size) {
  var out = new Buffer(size);
  var off = 0;

  // Process left-overs
  var c = this.buf;
  if (c) {
    if (c.length <= out.length) {
      c.copy(out, off);
      off += c.length;
      this.buf = null;
    } else {
      c.copy(out, off, 0, out.length);
      this.buf = c.slice(out.length);
      return out;
    }
  }

  while (off < size) {
    var c = this.hmac(this.secret).update(this.getA())
                                  .update(this.label)
                                  .update(this.seed)
                                  .digest('buffer');

    var maxCopy = out.length - off;
    if (c.length <= maxCopy) {
      c.copy(out, off);
    } else {
      // Generate left-over
      c.copy(out, off, 0, maxCopy);
      this.buf = c.slice(maxCopy);
    }
    off += c.length;
  }

  return out;
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
  ]);

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
