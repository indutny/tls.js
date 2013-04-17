var assert = require('assert');
var util = require('util');
var stream = require('stream');
var Buffer = require('buffer').Buffer;

function Parser(options) {
  stream.Transform.call(this);
  this._readableState.objectMode = true;

  this.options = options || {};
  this.buffer = [];
  this.bufferSize = 0;
};
util.inherits(Parser, stream.Transform);

module.exports = Parser;
Parser.create = function create(options) {
  return new this(options);
};

Parser.prototype._transform = function transform(chunk, encoding, callback) {
  assert.ok(Buffer.isBuffer(chunk), 'Only buffer writes are supported');

  if (chunk.length === 0) {
    // Ignore empty chunks
  } else {
    // Buffer chunk
    this.buffer.push(chunk);
    this.bufferSize += chunk.length;

    // Execute parser
    while (this.parse()) {
      // nop
    }
  }
  callback();
};

Parser.prototype.readInt = function readInt(size, offset) {
  var res = 0,
      end = offset + size;

  if (this.bufferSize < end || size !== 1 && size !== 2 && size !== 4) {
    // OOB
  } else if (this.buffer[0].length >= end) {
    // Fast-case: first buffer is the one to read from
    if (size === 1) {
      res = this.buffer[0][offset];
    } else if (size === 2) {
      res = this.buffer[0].readUInt16BE(offset, true);
    } else if (size === 4) {
      res = this.buffer[0].readUInt32BE(offset, true);
    }
  } else {
    var remaining = size,
        roffset = offset,
        i = 0,
        cur = 0;

    // Slow-case iterate through buffers
    while (true) {
      var chunk = this.buffer[i],
          new_cur = cur + chunk.length;

      if (remaining === size && new_cur >= end) {
        // We're lucky read everything from one buffer
        if (size === 1) {
          res = chunk[offset - cur];
        } else if (size === 2) {
          res = chunk.readUInt16BE(offset - cur, true);
        } else if (size === 4) {
          res = chunk.readUInt32BE(offset - cur, true);
        }
        break;
      } else {
        // Not so lucky, reading on the boundaries of multiple buffers
        while (remaining > 0 && new_cur > end - remaining) {
          res <<= 8;
          res |= chunk[roffset - cur];

          remaining--;
          roffset++;
        }

        if (remaining === 0) break;
      }

      cur = new_cur;
      i++;
    }
  }

  return res;
};

Parser.prototype.readBuffer = function readBuffer(size, offset) {
  var res = null,
      end = offset + size;

  if (this.bufferSize < end) {
    // OOB
  } else if (this.buffer[0].length >= end) {
    // Fast-case: first buffer is the one to read from
    return this.buffer[0].slice(offset, offset + size);
  } else {
    var remaining = size,
        toffset = 0,
        i = 0,
        cur = 0;

    // Slow-case iterate through buffers
    while (true) {
      var chunk = this.buffer[i],
          new_cur = cur + chunk.length;

      if (remaining === size && new_cur >= end) {
        // We're lucky read everything from one buffer
        res = chunk.slice(offset - cur, offset - cur + num);
        break;
      } else {
        // Not so lucky, reading on the boundaries of multiple buffers

        // Lazy-Allocate buffer
        if (!res) res = new Buffer(size);

        var to_copy = Math.min(chunk.length, remaining);
        chunk.copy(res, toffset, 0, to_copy);
        toffset += to_copy;
        remaining -= to_copy;

        if (remaining === 0) break;
      }

      cur = new_cur;
      i++;
    }
  }

  return res;
};

Parser.prototype.skip = function skip(num) {
  if (this.bufferSize <= num) {
    // Skip everything
    this.buffer = [];
    this.bufferSize = 0;
  } else {
    var remaining = num;
    while (remaining > 0) {
      var chunk = this.buffer[0];
      if (chunk.length <= remaining) {
        // Swipe buffer
        this.buffer.shift();
        remaining -= chunk.length;
      } else {
        // Slice buffer
        this.buffer[0] = chunk.slice(remaining);
        remaining = 0;
      }
    }
    this.bufferSize -= num;
  }
};

Parser.prototype.parse = function parse() {
  throw new Error('parse() not implemented');
};
