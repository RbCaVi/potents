import collections
import operator

import lib
import netdoc
import certificate

class RouterInfo:
  def __init__(self, id25519, exitpolicy, platform, fingerprint, hibernating, ntor_key, ipv6_exit_port_policy, contact):
    self.id25519 = id25519
    self.exitpolicy = exitpolicy
    self.platform = platform
    self.fingerprint = fingerprint
    self.hibernating = hibernating
    self.ntor_key = ntor_key
    self.ipv6_exit_port_policy = ipv6_exit_port_policy
    self.contact = contact

def parse_router(router_doc):
  lines = lib.Peekable(router_doc)
  name,ip,orport,socksport,dirport = netdoc.get_line_args_no_object('router', lines)
  (),id25519 = netdoc.get_line_args_with_object('identity-ed25519', 'ED25519 CERT', lines)
  id25519 = certificate.decode_ed_certificate(id25519)
  lines = [*lines]
  # there is no order requirement for the rest of the file (i think)
  # so i'm putting all of the lines into a dict
  grouped_lines = collections.defaultdict(list)
  for line in lines:
    grouped_lines[line.keyword].append(line)
  exitpolicy = [line for line in lines if line.keyword in ['accept', 'reject']]
  # i can ignore unrecognized keywords right?
  master25519 = lib.b64decode(lib.unwrap_line_args_no_object(lib.assert_one(grouped_lines['master-key-ed25519']))[0]) # ignore? - already included in `id25519`
  bandwidth = lib.unwrap_line_args_no_object(lib.assert_one(grouped_lines['bandwidth'])) # ignore
  platform = lib.optional(lib.unwrap_line_args_no_object)(lib.assert_optional(grouped_lines['platform']))
  published = ' '.join(lib.unwrap_line_args_no_object(lib.assert_one(grouped_lines['published']))) # ignore
  fingerprint = lib.optional_chain(lib.unwrap_line_args_no_object, ''.join, bytes.fromhex)(lib.assert_optional(grouped_lines['fingerprint']))
  hibernating = lib.optional_chain(lib.unwrap_line_args_no_object, operator.itemgetter(0), lib.tobool)(lib.assert_optional(grouped_lines['hibernating']))
  uptime = lib.optional_chain(lib.unwrap_line_args_no_object, operator.itemgetter(0), int)(lib.assert_optional(grouped_lines['uptime'])) # ignore
  (),tap_key = lib.optional(lib.unwrap_line_args_with_object_c('RSA PUBLIC KEY'))(lib.assert_optional(grouped_lines['onion-key'])) # ignore - used for obsolete 'tap' handshake
  (),tap_crosscert = lib.optional(lib.unwrap_line_args_with_object_c('CROSSCERT'))(lib.assert_optional(grouped_lines['onion-key-crosscert'])) # ignore
  ntor_key = lib.b64decode(lib.unwrap_line_args_no_object(lib.assert_one(grouped_lines['ntor-onion-key']))[0])
  bit,ntor_crosscert = lib.optional(lib.unwrap_line_args_with_object_c('ED25519 CERT'))(lib.assert_optional(grouped_lines['ntor-onion-key-crosscert'])) # ignore i guess?
  (),signing_key = lib.unwrap_line_args_with_object_c('RSA PUBLIC KEY')(lib.assert_optional(grouped_lines['onion-key'])) # ignore - obsolete
  ipv6_exit_port_policy = [lib.unwrap_line_args_no_object(l) for l in grouped_lines['ipv6-policy']]
  overloaded = lib.optional(lib.unwrap_line_args_no_object)(lib.assert_optional(grouped_lines['overload-general'])) # ignore
  contact = lib.optional_chain(lib.unwrap_line_args_no_object, ' '.join)(lib.assert_optional(grouped_lines['contact']))
  # bridge-distribution-request
  # family
  # family-cert
  # eventdns
  # extra-info-digest
  # hidden-service-dir
  # allow-single-hop-exits
  # tunnelled-dir-server
  # router-sig-ed25519
  # router-signature
  # (i gave up (i'll do these later if i need them)) - https://spec.torproject.org/dir-spec/server-descriptor-format.html
  return RouterInfo(id25519, exitpolicy, platform, fingerprint, hibernating, ntor_key, ipv6_exit_port_policy, contact)