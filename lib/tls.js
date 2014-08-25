var tls = exports;

tls.utils = require('./tls/utils');

tls.constants = require('./tls/constants');
tls.state = require('./tls/state');
tls.parser = require('./tls/parser');
tls.framer = require('./tls/framer');

tls.context = require('./tls/context');
tls.socket = require('./tls/socket');

tls.provider = { node: null };
Object.keys(tls.provider).forEach(function(name) {
  Object.defineProperty(tls.provider, name, {
    enumerable: true,
    configurable: true,
    get: function() {
      var provider = require('./tls/provider/' + name);
      Object.defineProperty(this, name, {
        enumerable: true,
        configurable: true,
        value: provider
      });
      return provider;
    }
  });
});
