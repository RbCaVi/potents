import datetime
import base64

import lib

def parse_consensus(consensus_doc):
  # consensusdoc is a list of lines, as returned by parse_netdoc()
  # i'm assuming it's in the same order as in the spec at https://spec.torproject.org/dir-spec/consensus-formats.html
  # also that it doesn't have any extra arguments not mentioned in the spec
  lines = lib.Peekable(consensus_doc)
  consensus_version, = lib.get_line_args_no_object('network-status-version', lines)
  assert consensus_version == '3', f'unrecognized consensus version {consensus_version}'
  consensus_type, = lib.get_line_args_no_object('vote-status', lines)
  assert consensus_type == 'consensus', f'unrecognized consensus type {consensus_type}' # the spec says 'vote' or 'status' but the consensus i got has 'consensus'
  consensus_method, = lib.get_line_args_optional_no_object('consensus-method', lines, [1]) # ignore
  
  # these are naive datetime - utc timezone
  valid_after = datetime.datetime.fromisoformat('T'.join(lib.get_line_args_no_object('valid-after', lines)))
  fresh_until = datetime.datetime.fromisoformat('T'.join(lib.get_line_args_no_object('fresh-until', lines)))
  valid_until = datetime.datetime.fromisoformat('T'.join(lib.get_line_args_no_object('valid-until', lines)))
  
  # i don't care about these
  voting_delays = lib.get_line_args_no_object('voting-delay', lines)
  client_versions = lib.get_line_args_no_object('client-versions', lines)
  server_versions = lib.get_line_args_no_object('server-versions', lines)
  
  known_flags = lib.get_line_args_no_object('known-flags', lines)
  
  # i don't care about these
  # maybe the client ones but i'll deal with that if it's a problem
  rec_client_protos = lib.params_to_dict(lib.get_line_args_optional_no_object('recommended-client-protocols', lines, []))
  rec_relay_protos = lib.params_to_dict(lib.get_line_args_optional_no_object('recommended-relay-protocols', lines, []))
  req_client_protos = lib.params_to_dict(lib.get_line_args_optional_no_object('required-client-protocols', lines, []))
  req_relay_protos = lib.params_to_dict(lib.get_line_args_optional_no_object('required-relay-protocols', lines, []))

  params = lib.params_to_dict(lib.get_line_args_optional_no_object('params', lines, []))
  
  srv_prev_reveals,srv_prev = lib.get_line_args_optional_no_object('shared-rand-previous-value', lines)
  srv_prev_reveals = int(srv_prev_reveals)
  srv_prev = base64.b64decode(srv_prev)
  assert len(srv_prev) == 32, f'shared random value of length {len(srv_prev)} in consensus (should be 32)' # 256 bits or 32 bytes
  
  srv_curr_reveals,srv_curr = lib.get_line_args_optional_no_object('shared-rand-current-value', lines)
  srv_curr_reveals = int(srv_curr_reveals)
  srv_curr = base64.b64decode(srv_curr)
  assert len(srv_curr) == 32, f'shared random value of length {len(srv_curr)} in consensus (should be 32)' # 256 bits or 32 bytes
  
  # i don't care about this now
  dirs = []
  while lines.peek()[0] == 'dir-source':
    dir_name,dir_fingerprint,dir_hostname,dir_ip,dir_dirport,dir_orport = lib.get_line_args_no_object('dir-source', lines)
    dir_contact = ' '.join(lib.get_line_args_no_object('contact', lines))
    vote_digest, = lib.get_line_args_no_object('vote-digest', lines) # don't really care about this
    dirs.append((dir_name, dir_fingerprint, dir_hostname, dir_ip, dir_dirport, dir_orport, dir_contact))
  
  routers = []
  while lines.peek()[0] == 'r':
    # i'm ignoring r_descr_digest (digest of most recent descriptor), r_pub1, r_pub2 (publication date, only meaningful in votes)
    r_name,r_id_hash,r_descr_digest,r_pub1,r_pub2,r_ip,r_orport,r_dirport = lib.get_line_args_no_object('r', lines)
    r_id_hash = base64.b64decode(r_id_hash + '=') # unpadded :(
    addrs = [] # ignore
    while lines.peek()[0] == 'a':
      r_extra_addr, = lib.get_line_args_no_object('a', lines)
      addrs.append(r_extra_addr)
    r_flags = lib.get_line_args_no_object('s', lines)
    r_version = ' '.join(lib.get_line_args_optional_no_object('v', lines, []))
    r_protos = lib.params_to_dict(lib.get_line_args_no_object('pr', lines))
    r_bandwidth = lib.params_to_dict(lib.get_line_args_optional_no_object('w', lines)) # ignore
    r_ports = lib.get_line_args_optional_no_object('p', lines)
    routers.append((r_name, r_id_hash, r_ip, r_orport, r_dirport, r_flags, r_version, r_protos, r_ports))
  
  () = lib.get_line_args_no_object('directory-footer', lines)
  bandwidth_weights = lib.params_to_dict(lib.get_line_args_optional_no_object('bandwidth-weights', lines)) # ignore
  
  signatures = [] # ignore # i'm not verifying these :)
  for line in lines:
    assert line[0] == 'directory-signature'
    signature_data = line[1]
    assert line[2] == 'SIGNATURE'
    if len(signature_data) == 3:
      hash_alg,id_key,signing_key_digest = signature_data
    else:
      hash_alg,id_key,signing_key_digest = 'sha1', *signature_data
    signatures.append((hash_alg, id_key, signing_key_digest, line[3]))
  
  return valid_after, fresh_until, valid_until, known_flags, rec_client_protos, req_client_protos, params, srv_prev, srv_curr, routers