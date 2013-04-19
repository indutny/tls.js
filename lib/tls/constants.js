var constants = exports;

constants.recordType = {
  20: 'change_cipher_spec',
  21: 'alert',
  22: 'handshake',
  23: 'application_data'
};

constants.alertLevel = {
  1: 'warning',
  2: 'fatal'
};

constants.alertDescription = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  21: 'decryption_failed_RESERVED',
  22: 'record_overflow',
  30: 'decompression_failure',
  40: 'handshake_failure',
  41: 'no_certificate_RESERVED',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  52: 'export_restriction_RESERVED',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  90: 'user_canceled',
  100: 'no_renegotiation',
  110: 'unsupported_extension'
};

constants.handshakeType = {
  0: 'hello_request',
  1: 'client_hello',
  2: 'server_hello',
  11: 'certificate',
  12: 'server_key_exchange',
  13: 'certificate_request',
  14: 'server_hello_done',
  15: 'certificate_verify',
  16: 'client_key_exchange',
  20: 'finished',
  67: 'next_protocol'
};

constants.extensionType = {
  0: 'server_name',
  1: 'max_fragment_length',
  2: 'client_certificate_url',
  3: 'trusted_ca_keys',
  4: 'trusted_hmac',
  5: 'status_request',
  6: 'user_mapping',
  7: 'client_authz',
  8: 'server_authz',
  9: 'cert_type',
  10: 'elliptic_curves',
  11: 'ec_point_formats',
  12: 'srp',
  13: 'signature_algorithms',
  14: 'use_srtp',
  15: 'heartbeat',
  16: 'application_level_protocol_negotation',
  17: 'status_request_v2',
  18: 'signed_certificate_timestamp',
  35: 'session_ticket_tls',
  13172: 'next_protocol_negotation',
  65281: 'renegotation_info'
};

constants.cipherSuite = {
  0x0: 'NULL_WITH_NULL_NULL',
  0x1: 'RSA_WITH_NULL_MD5',
  0x2: 'RSA_WITH_NULL_SHA',
  0x3b: 'RSA_WITH_NULL_SHA256',
  0x4: 'RSA_WITH_RC4_128_MD5',
  0x5: 'RSA_WITH_RC4_128_SHA',
  0xa: 'RSA_WITH_3DES_EDE_CBC_SHA',
  0x2f: 'RSA_WITH_AES_128_CBC_SHA',
  0x35: 'RSA_WITH_AES_256_CBC_SHA',
  0x3c: 'RSA_WITH_AES_128_CBC_SHA256',
  0x3d: 'RSA_WITH_AES_256_CBC_SHA256',
  0xd: 'DH_DSS_WITH_3DES_EDE_CBC_SHA',
  0x10: 'DH_RSA_WITH_3DES_EDE_CBC_SHA',
  0x13: 'DHE_DSS_WITH_3DES_EDE_CBC_SHA',
  0x16: 'DHE_RSA_WITH_3DES_EDE_CBC_SHA',
  0x30: 'DH_DSS_WITH_AES_128_CBC_SHA',
  0x31: 'DH_RSA_WITH_AES_128_CBC_SHA',
  0x32: 'DHE_DSS_WITH_AES_128_CBC_SHA',
  0x33: 'DHE_RSA_WITH_AES_128_CBC_SHA',
  0x36: 'DH_DSS_WITH_AES_256_CBC_SHA',
  0x37: 'DH_RSA_WITH_AES_256_CBC_SHA',
  0x38: 'DHE_DSS_WITH_AES_256_CBC_SHA',
  0x39: 'DHE_RSA_WITH_AES_256_CBC_SHA',
  0x3e: 'DH_DSS_WITH_AES_128_CBC_SHA256',
  0x3f: 'DH_RSA_WITH_AES_128_CBC_SHA256',
  0x40: 'DHE_DSS_WITH_AES_128_CBC_SHA256',
  0x67: 'DHE_RSA_WITH_AES_128_CBC_SHA256',
  0x68: 'DH_DSS_WITH_AES_256_CBC_SHA256',
  0x69: 'DH_RSA_WITH_AES_256_CBC_SHA256',
  0x6a: 'DHE_DSS_WITH_AES_256_CBC_SHA256',
  0x6b: 'DHE_RSA_WITH_AES_256_CBC_SHA256',
  0x18: 'DH_anon_WITH_RC4_128_MD5',
  0x1b: 'DH_anon_WITH_3DES_EDE_CBC_SHA',
  0x34: 'DH_anon_WITH_AES_128_CBC_SHA',
  0x3a: 'DH_anon_WITH_AES_256_CBC_SHA',
  0x6c: 'DH_anon_WITH_AES_128_CBC_SHA256',
  0x6d: 'DH_anon_WITH_AES_256_CBC_SHA256'
};
