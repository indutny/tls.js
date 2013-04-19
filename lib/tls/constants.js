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
