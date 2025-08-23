# tor <3

# notes
# KP / KS - public and private (secret) keys for asymmetric cipher
# K - key for a symmetric cipher
# N - nonce - random or hashed from other inputs
# H(m) - cryptographic hash of m
# base32 has no padding
# integers are big endian - struct.pack('>*', *)

import ssl
import time
import socket
import struct
import hashlib
import random
import requests
import os
import datetime
import pickle
import cryptography.hazmat.primitives.asymmetric.x25519
import secrets
import hmac

import tor_dirs
import netdoc
import consensus
import routers
import certificate
import lib

KEY_LEN = 16 # size of stream cipher key in bytes

HASH_LEN = 20 # length of the hash output in bytes

FIXED_PAYLOAD_LEN = 509 # longest payload in bytes

def sha256(data):
  return hashlib.sha256(data).digest()

def sha3_256(data):
  return hashlib.sha3_256(data).digest()

# skipping the 1.1 keys and names section for now

# cell commands
# fixed length
PADDING = 0 # Padding
CREATE = 1 # Create a circuit
CREATED = 2 # Acknowledge create
RELAY = 3 # End-to-end data
DESTROY = 4 # Stop using a circuit
CREATE_FAST = 5 # Create a circuit, no KP
CREATED_FAST = 6 # Circuit created, no KP
NETINFO = 8 # Time and address info
RELAY_EARLY = 9 # End-to-end data; limited
CREATE2 = 10 # Extended CREATE cell
CREATED2 = 11 # Extended CREATED cell
PADDING_NEGOTIATE = 12 # Padding negotiation
fixed_length_commands = [PADDING, CREATE, CREATED, RELAY, DESTROY, CREATE_FAST, CREATED_FAST, NETINFO, RELAY_EARLY, CREATE2, CREATED2, PADDING_NEGOTIATE]

# variable length
VERSIONS = 7 # Negotiate proto version
VPADDING = 128 # Variable-length padding
CERTS = 129 # Certificates
AUTH_CHALLENGE = 130 # Challenge value
AUTHENTICATE = 131 # Client authentication
variable_length_commands = [VERSIONS, VPADDING, CERTS, AUTH_CHALLENGE, AUTHENTICATE]

# note: i didn't include AUTHORIZE because it says not used

def pack_fixed_length_cell(circid, command, payload, version):
  assert len(payload) == FIXED_PAYLOAD_LEN, f'payload of wrong length: {len(payload)}'
  if version < 4:
    return struct.pack('>HB509s', circid, command, payload) # circuit id is 2 bytes for version less than 4
  else:
    return struct.pack('>IB509s', circid, command, payload) # and 4 bytes otherwise

def pack_variable_length_cell(circid, command, payload, version):
  if version < 4:
    return struct.pack('>HBH', circid, command, len(payload)) + payload # circuit id is 2 bytes for version less than 4
  else:
    return struct.pack('>IBH', circid, command, len(payload)) + payload # and 4 bytes otherwise

def pack_cell(circid, command, payload, version):
  if command in fixed_length_commands:
    return pack_fixed_length_cell(circid, command, payload, version)
  elif command in variable_length_commands:
    return pack_variable_length_cell(circid, command, payload, version)
  else:
    raise NotImplementedError

class Cell:
  def __init__(self, circid, command, payload):
    self.circid = circid
    self.command = command
    self.payload = payload
  
  def pack(self, version):
    return pack_cell(self.circid, self.command, self.payload, version)
  
  def __repr__(self):
    return f'Cell({self.circid}, {self.command}, {self.payload})'

class RelayCell:
  def __init__(self, streamid, command, payload):
    self.streamid = streamid
    self.command = command
    self.payload = payload
  
  def __repr__(self):
    return f'Cell({self.streamid}, {self.command}, {self.payload})'

def get_context():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.VerifyMode.CERT_NONE
  return context

torcontext = get_context() # doesn't need to be customizable right?

def unpack_cell(data, version):
  if version < 4:
    if len(data) < 2 + 1: # circuit id + command - i'm going to struct.unpack() it
      return None, data
    circuitid,command = struct.unpack_from('>HB', data)
    offset = 2 + 1
  else:
    if len(data) < 4 + 1: # circuit id + command - i'm going to struct.unpack() it
      return None, data
    circuitid,command = struct.unpack_from('>IB', data)
    offset = 4 + 1
  if command in fixed_length_commands:
    if len(data) < offset + FIXED_PAYLOAD_LEN:
      return None, data
    payload = lib.bytes_from(FIXED_PAYLOAD_LEN, data, offset)
    offset += FIXED_PAYLOAD_LEN
    return Cell(circuitid, command, payload), data[offset:]
  elif command in variable_length_commands:
    if len(data) < offset + 2:
      return None, data
    payload_len, = struct.unpack_from('>H', data, offset)
    offset += 2
    if len(data) < offset + payload_len:
      return None, data
    payload = lib.bytes_from(payload_len, data, offset)
    offset += payload_len
    return Cell(circuitid, command, payload), data[offset:]
  else:
    raise NotImplementedError

# read and write cells easily
# plagiarized from myself <3333
class CellSocket:
  def __init__(self, conn):
    self.conn = conn
    self.buffer = b''
    self.version = 0

  def recv(self):
    while True:
      cell,self.buffer = unpack_cell(self.buffer, self.version)
      if cell is not None:
        if cell.command != PADDING:
          return cell
        else:
          print("padding", cell)
      while True: # nested infinite while loop >:)
        # basically wait until a chunk has been recieved
        chunk = self.conn.recv(2048)
        if chunk != b'':
          self.buffer += chunk
          break
        else:
          print(self.buffer)
          time.sleep(1)
          print("Not enough data for a complete cell, waiting...")
          # uhh timeout maybe???

  def send(self, cell):
    self.conn.send(cell.pack(self.version))
  
  def close(self):
    self.conn.close()

def encode_versions_cell(versions):
  return Cell(0, VERSIONS, b''.join(struct.pack('>H', v) for v in versions))

def decode_versions_cell(cell):
  assert cell.command == VERSIONS, 'attempted to decode non-VERSIONS cell using decode_versions_cell()'
  return {v for v, in struct.iter_unpack('>H', cell.payload)}

# certificate types
#TLS_LINK_X509 = 1 # obsolete
#RSA_ID_X509 = 2 # obsolete
#LINK_AUTH_X509 = 3 # obsolete
IDENTITY_V_SIGNING = 4
SIGNING_V_TLS_CERT = 5
#SIGNING_V_LINK_AUTH = 6 # not used right now
#RSA_ID_V_IDENTITY = 7 # not used right now
#BLINDED_ID_V_SIGNING = 8 # not used right now
#HS_IP_V_SIGNING = 9 # not used right now
#NTOR_CC_IDENTITY = 10 # not used right now
#HS_IP_CC_SIGNING = 11 # not used right now
#FAMILY_V_IDENTITY = 12 # not used right now

def decode_certs_cell(cell):
  assert cell.command == CERTS, 'attempted to decode non-CERTS cell using decode_certs_cell()'
  n, = struct.unpack_from('>B', cell.payload) # number of certificates
  offset = 1
  certs = {}
  for i in range(n):
    cert_type,cert_len = struct.unpack_from('>BH', cell.payload, offset)
    offset += 3
    cert_data = lib.bytes_from(cert_len, cell.payload, offset)
    offset += cert_len
    if cert_type == IDENTITY_V_SIGNING:
      cert_data = certificate.decode_ed_certificate(cert_data)
      assert cert_data.cert_type == cert_type, f'mismatched certificate type [{cert_data.cert_type}] inside Ed certificate of type 4 in CERTS_CELL'
    if cert_type == SIGNING_V_TLS_CERT:
      cert_data = certificate.decode_ed_certificate(cert_data)
      assert cert_data.cert_type == cert_type, f'mismatched certificate type [{cert_data.cert_type}] inside Ed certificate of type 5 in CERTS_CELL'
    # i'm going to ignore all the other certificates anyway so i don't have to process them
    assert cert_type not in certs, f'duplicate certificate of type {cert_type} in CERTS cell'
    certs[cert_type] = cert_data
  return certs

def unpack_addr_from(data, offset):
  # returns an ipv4 or ipv6 address as a string
  # and the new offset
  addr_type,addr_len = struct.unpack_from('>BB', data, offset)
  offset += 2
  assert (addr_type, addr_len) in [(4, 4), (6, 16)], f'unrecognized atype, alen combination: {addr_type}, {addr_len}'
  addr_data = lib.bytes_from(addr_len, data, offset)
  offset += addr_len
  if addr_type == 4:
    addr = socket.inet_ntop(socket.AF_INET, addr_data)
  if addr_type == 6:
    addr = socket.inet_ntop(socket.AF_INET6, addr_data)
  return addr, offset

def decode_netinfo_cell(cell):
  assert cell.command == NETINFO, 'attempted to decode non-NETINFO cell using decode_netinfo_cell()'
  timestamp, = struct.unpack_from('>I', cell.payload)
  offset = 4
  other_addr,offset = unpack_addr_from(cell.payload, offset) # (from the router's perspective)
  n, = struct.unpack_from('>B', cell.payload, offset) # number of my addresses (from the router's perspective)
  offset += 1
  my_addrs = []
  for i in range(n):
    my_addr,offset = unpack_addr_from(cell.payload, offset)
    my_addrs.append(my_addr)
  return timestamp, other_addr, my_addrs

def encode_netinfo_cell(addr):
  # https://spec.torproject.org/tor-spec/negotiating-channels.html#NETINFO-cells
  # taking the recommendations - send 00 00 00 00 timestamp and no addresses
  # only ipv4 addresses supported
  return Cell(0, NETINFO, pad_fixed_length_data(struct.pack('>IBB4sB', 0, 4, 4, socket.inet_pton(socket.AF_INET, addr), 0)))

# connects to the relay without authenticating
# takes a (ip, port) pair
def connect(relay):
  s = torcontext.wrap_socket(socket.socket(socket.AF_INET))
  s.connect(relay)
  conn = CellSocket(s)
  
  lversions = {4}
  conn.send(encode_versions_cell(lversions))
  rversions = decode_versions_cell(conn.recv())
  conn.version = max(lversions & rversions)
  
  certs = decode_certs_cell(conn.recv())
  
  assert certs[IDENTITY_V_SIGNING].key_type == 1, f'incorrect key type {certs[IDENTITY_V_SIGNING].key_type} for IDENTITY_V_SIGNING certificate'
  KP_relayid_ed = certs[IDENTITY_V_SIGNING].exts[4]
  assert certs[IDENTITY_V_SIGNING].verify(KP_relayid_ed)
  KP_relaysign_ed = certificate.ed_key(certs[IDENTITY_V_SIGNING].key)
  
  assert certs[SIGNING_V_TLS_CERT].key_type in [1, 3], f'incorrect key type {certs[IDENTITY_V_SIGNING].key_type} for SIGNING_V_TLS_CERT certificate' # technically it should be 3, but old tor put 1 for no reason so
  assert certs[SIGNING_V_TLS_CERT].verify(KP_relaysign_ed)
  servercert = s.getpeercert(binary_form = True)
  assert certs[SIGNING_V_TLS_CERT].key == sha256(servercert)
  
  challenge = conn.recv()
  assert challenge.command == AUTH_CHALLENGE, 'did not recieve expected AUTH_CHALLENGE cell while initializing connection'
  
  router_timestamp,my_addr,router_addrs = decode_netinfo_cell(conn.recv())
  
  my_timestamp = int(time.time())
  
  print(my_timestamp, router_timestamp, my_addr, router_addrs)
  
  conn.send(encode_netinfo_cell(relay[0]))
  
  return conn

HANDSHAKE_TAP = 0x0000 # obsolete
# (0x0001 is reserved)
HANDSHAKE_NTOR = 0x0002
HANDSHAKE_NTOR3 = 0x0003

def pad_fixed_length_data(data):
  return data + bytes(FIXED_PAYLOAD_LEN - len(data))

def encode_ntor_handshake(fingerprint, ntor_key_pub, temp_key_pub):
  return fingerprint + ntor_key_pub.public_bytes_raw() + temp_key_pub.public_bytes_raw()

def encode_create2_cell(circid, handshake_type, data):
  return Cell(circid, CREATE2, pad_fixed_length_data(struct.pack('>HH', handshake_type, len(data)) + data))

def decode_created2_cell(cell):
  assert cell.command == CREATED2, 'attempted to decode non-CREATED2 cell using decode_created2_cell()'
  data_len, = struct.unpack_from('>H', cell.payload)
  offset = 2
  data = lib.bytes_from(data_len, cell.payload, offset)
  return data

def decode_ntor_response(data):
  assert len(data) == 64
  server_temp_key_pub = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(data[0:32])
  auth_hashed_server = data[32:64]
  return server_temp_key_pub, auth_hashed_server

NTOR_PROTO_ID = b'ntor-curve25519-sha256-1'

def tor_hmac(message, key):
  return hmac.digest(key, message, hashlib.sha256)

def ntor_kdf(seed, m_expand, chunks):
  # https://spec.torproject.org/tor-spec/setting-circuit-keys.html#kdf-rfc5869
  # also used for ntor-hs handshake - hence the m_expand parameter
  ks = [] # total key material
  k = b'' # the chunk at each iteration (used to calculate the next chunk)
  for i in range(1, chunks + 1): # because they start the counter at 1
    k = tor_hmac(k + m_expand + bytes([i]), seed)
    ks.append(k)
  return b''.join(ks)

class StreamCipher: # 128 bit AES - stream mode - IV all 0
  def __init__(self, key):
    cipher = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(key), cryptography.hazmat.primitives.ciphers.modes.CTR(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'))
    self.encryptor = cipher.encryptor()
    self.decryptor = cipher.decryptor()
  
  def encrypt(self, data):
    return self.encryptor.update(data)
  
  def decrypt(self, data):
    return self.decryptor.update(data)

class RelayState:
  def __init__(self, digest_forward, digest_backward, key_forward, key_backward, hash_func = hashlib.sha1):
    self.digest_forward = hash_func(digest_forward)
    self.digest_backward = hash_func(digest_backward)
    self.cipher_forward = StreamCipher(key_forward)
    self.cipher_backward = StreamCipher(key_backward)
  
  def update_forward(self, cell):
    # update this relay's stored digest and the digest field in a cell destined for this relay
    assert cell.command in [RELAY, RELAY_EARLY], 'passed a non RELAY/RELAY_EARLY cell to RelayState.update_forward()'
    self.digest_forward.update(cell.payload)
    cell.payload = cell.payload[0:5] + self.digest_forward.digest()[:4] + cell.payload[9:]
  
  def check_backward(self, cell):
    # check if a cell is from this relay and update this relay's stored digest if it is
    assert cell.command in [RELAY, RELAY_EARLY], 'passed a non RELAY/RELAY_EARLY cell to RelayState.check_backward()'
    if cell.payload[1:3] != b'\0\0': # `recognized` field does not pass
      return False
    digest_payload = cell.payload[0:5] + b'\0\0\0\0' + cell.payload[9:]
    digest_backward_temp = self.digest_backward.copy()
    digest_backward_temp.update(digest_payload)
    if digest_backward_temp.digest()[:4] != cell.payload[5:9]: # `digest` field does not pass
      return False
    self.digest_backward = digest_backward_temp
    return True
  
  def encrypt_forward(self, cell):
    assert cell.command in [RELAY, RELAY_EARLY], 'passed a non RELAY/RELAY_EARLY cell to RelayState.encrypt_forward()'
    return Cell(cell.circid, cell.command, self.cipher_forward.encrypt(cell.payload))
  
  def decrypt_backward(self, cell):
    assert cell.command in [RELAY, RELAY_EARLY], 'passed a non RELAY/RELAY_EARLY cell to RelayState.encrypt_forward()'
    return Cell(cell.circid, cell.command, self.cipher_backward.decrypt(cell.payload))

def encode_relay_cell(circid, command, cell):
  assert command in [RELAY, RELAY_EARLY], 'attempted to encode non-RELAY/RELAY_EARLY cell using encode_relay_cell()'
  padding = bytes(FIXED_PAYLOAD_LEN - 11 - len(cell.payload)) # this should be at least partially random but i was lazy to do that
  # the two 0 fields are `recognized` and `digest`
  return Cell(circid, command, struct.pack('>BHHIH', cell.command, 0, cell.streamid, 0, len(cell.payload)) + cell.payload + padding)

def decode_relay_cell(cell):
  assert cell.command in [RELAY, RELAY_EARLY], 'attempted to decode non-RELAY/RELAY_EARLY cell using decode_relay_cell()'
  command,recognized,streamid,digest,length = struct.unpack_from('>BHHIH', cell.payload)
  # i don't need to check `recognized` or `digest` here - it's already checked by RelayState
  offset = 11
  payload = lib.bytes_from(length, cell.payload, offset)
  return RelayCell(streamid, command, payload)

class RelayChain:
  def __init__(self, relays):
    self.relays = relays
  
  def encrypt_forward(self, cell, i = None):
    # takes an already encoded RELAY/RELAY_EARLY cell
    # and encrypts it to send
    # use like conn.send(chain.encrypt_forward(cell))
    if i is None:
      i = len(self.relays) - 1
    self.relays[i].update_forward(cell)
    for relay in reversed(self.relays):
      cell = relay.encrypt_forward(cell)
    return cell
    
  
  def decrypt_backward(self, cell):
    # cell is the RELAY/RELAY_EARLY cell straight from conn.recv()
    # use like chain.decrypt_backward(conn.recv())
    for i,relay in enumerate(self.relays):
      cell = relay.decrypt_backward(cell)
      if relay.check_backward(cell):
        return i, cell
    assert False, 'undecryptable cell :('

  def decrypt_backward_from_end(self, cell):
    # make sure the cell comes from the end
    i,cell = self.decrypt_backward(cell)
    assert i == len(self.relays) - 1, 'attempted to decrypt a cell that didn\'t come from the end with RelayState.decrypt_backward_from_end()'
    return cell

# two halves because this is used in CREATE2 and RELAY_EARLY(EXTEND2) cells

def handshake_ntor_1(fingerprint, ntor_key_pub_bytes):
  # ntor_key_pub is B
  # temp_key_pub is X
  # server_temp_key_pub is Y
  ntor_key_pub = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(ntor_key_pub_bytes)
  
  temp_key_sec = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
  temp_key_pub = temp_key_sec.public_key()
  
  return (fingerprint, ntor_key_pub, temp_key_sec, temp_key_pub), encode_ntor_handshake(fingerprint, ntor_key_pub, temp_key_pub)

def handshake_ntor_2(data, response):
  fingerprint,ntor_key_pub,temp_key_sec,temp_key_pub = data
  server_temp_key_pub,auth_hashed_server = decode_ntor_response(response)
  
  secret_input = temp_key_sec.exchange(server_temp_key_pub) + temp_key_sec.exchange(ntor_key_pub) + fingerprint + ntor_key_pub.public_bytes_raw() + temp_key_pub.public_bytes_raw() + server_temp_key_pub.public_bytes_raw() + NTOR_PROTO_ID
  secret_hashed = tor_hmac(secret_input, NTOR_PROTO_ID + b':verify')
  auth_input = secret_hashed + fingerprint + ntor_key_pub.public_bytes_raw() + server_temp_key_pub.public_bytes_raw() + temp_key_pub.public_bytes_raw() + NTOR_PROTO_ID + b'Server'
  assert auth_hashed_server == tor_hmac(auth_input, NTOR_PROTO_ID + b':mac')
  
  key_seed = tor_hmac(secret_input, NTOR_PROTO_ID + b':key_extract')
  keys_source = ntor_kdf(key_seed, NTOR_PROTO_ID + b':key_expand', 3) # 2 * SHA1_LEN (20) + 2 * KEY_LEN (16) / H_LENGTH (32) = 3 chunks
  
  offset = 0
  digest_forward = lib.bytes_from(20, keys_source, offset)
  offset += 20
  digest_backward = lib.bytes_from(20, keys_source, offset)
  offset += 20
  key_forward = lib.bytes_from(16, keys_source, offset)
  offset += 16
  key_backward = lib.bytes_from(16, keys_source, offset)
  offset += 16
  
  return RelayState(digest_forward, digest_backward, key_forward, key_backward)

def create_first_hop_ntor(conn, fingerprint, ntor_key_pub_bytes):
  data,handshake = handshake_ntor_1(fingerprint, ntor_key_pub_bytes)
  
  circid = 0x81818181 | secrets.randbits(31) # not sure why i have 0x81818181 - the only thing i need is that the top bit is 1 and the rest are not all 0
  
  conn.send(encode_create2_cell(circid, HANDSHAKE_NTOR, handshake))
  response = decode_created2_cell(conn.recv())
  
  relay_state = handshake_ntor_2(data, response)
  
  return RelayChain([relay_state]), circid

BEGIN = 1 # Open a stream
DATA = 2 # Transmit data
END = 3 # Close a stream
CONNECTED = 4 # Stream has successfully opened
SENDME = 5 # Acknowledge traffic
EXTEND = 6 # Extend a circuit with TAP (obsolete)
EXTENDED = 7 # Finish extending a circuit with TAP (obsolete)
TRUNCATE = 8 # Remove nodes from a circuit (unused)
TRUNCATED = 9 # Report circuit truncation (unused)
DROP = 10 # Long-range padding
RESOLVE = 11 # Hostname lookup
RESOLVED = 12 # Hostname lookup reply
BEGIN_DIR = 13 # Open stream to directory cache
EXTEND2 = 14 # Extend a circuit
EXTENDED2 = 15 # Finish extending a circuit
# 16-18 are reserved
CONFLUX_LINK = 19 # Link circuits into a bundle
CONFLUX_LINKED = 20 # Acknowledge link request
CONFLUX_LINKED_ACK = 21 # Acknowledge CONFLUX_LINKED message (for timing)
CONFLUX_SWITCH = 22 # Switch between circuits in a bundle
ESTABLISH_INTRO = 32 # Create introduction point
ESTABLISH_RENDEZVOUS = 33 # Create rendezvous point
INTRODUCE1 = 34 # Introduction request (to intro point)
INTRODUCE2 = 35 # Introduction request (to service)
RENDEZVOUS1 = 36 # Rendezvous request (to rendezvous point)
RENDEZVOUS2 = 37 # Rendezvous request (to client)
INTRO_ESTABLISHED = 38 # Acknowledge ESTABLISH_INTRO
RENDEZVOUS_ESTABLISHED = 39 # Acknowledge ESTABLISH_RENDEZVOUS
INTRODUCE_ACK = 40 # Acknowledge INTRODUCE1
PADDING_NEGOTIATE = 41 # Negotiate circuit padding
PADDING_NEGOTIATED = 42 # Negotiate circuit padding
XOFF = 43 # Stream-level flow control
XON = 44 # Stream-level flow control

def encode_relay_extend2_cell(handshake_type, address, fingerprint, data):
  # address should be a tuple of (ip, port)
  # using the tap identity key fingerprint because i already have that
  # the ed25519 key would have to be extracted from the router document (which i have, though)
  return RelayCell(0, EXTEND2, struct.pack('>BBB4sHBB20sHH', 2, 0, 6, socket.inet_pton(socket.AF_INET, address[0]), address[1], 2, 20, fingerprint, handshake_type, len(data)) + data)

def decode_relay_extended2_cell(cell):
  assert cell.command == EXTENDED2, 'attempted to decode non-EXTENDED2 cell using decode_extended2_cell()'
  data_len, = struct.unpack_from('>H', cell.payload)
  offset = 2
  data = lib.bytes_from(data_len, cell.payload, offset)
  return data

def create_next_hop_ntor(conn, relays, circid, address, fingerprint, ntor_key_pub_bytes):
  data,handshake = handshake_ntor_1(fingerprint, ntor_key_pub_bytes)
  
  conn.send(relays.encrypt_forward(encode_relay_cell(circid, RELAY_EARLY, encode_relay_extend2_cell(HANDSHAKE_NTOR, address, fingerprint, handshake))))
  response = decode_relay_extended2_cell(decode_relay_cell(relays.decrypt_backward_from_end(conn.recv())))
  
  relay_state = handshake_ntor_2(data, response)
  
  relays.relays.append(relay_state)
  
  return relays

def encode_relay_begin_cell(streamid, addrport):
  # i'm not going to set flags ;)
  return RelayCell(streamid, BEGIN, bytes(addrport, 'utf-8') + b'\0')

def encode_relay_data_cell(streamid, payload):
  return RelayCell(streamid, DATA, payload)

def decode_relay_connected_cell(cell):
  addrbytes,ttl = struct.unpack('>4sI', cell.payload)
  return socket.inet_ntop(socket.AF_INET, addrbytes), ttl

os.makedirs('cache', exist_ok = True)
os.makedirs('cache/routers', exist_ok = True)

def get_consensus():
  if not os.path.exists('cache/consensus'):
    name,addr,fingerprint = random.choice(tor_dirs.auth_dirs)
    print(f'downloading consensus from {name} ({addr})')
    consensus_response = requests.get(f'http://{addr}/tor/status-vote/current/consensus')
    consensus_data = consensus_response.text
    print(f'response code {consensus_response.status_code}')
    with open('cache/consensus.txt', 'w') as f:
      f.write(consensus_data)
    consensus_doc = netdoc.parse_netdoc(consensus_data)
    consensus_parsed = consensus.parse_consensus(consensus_doc)
    with open('cache/consensus', 'wb') as f:
      pickle.dump(consensus_parsed, f, 0)
  else:
    print('using cached consensus')
    with open('cache/consensus', 'rb') as f:
      consensus_parsed = pickle.load(f)
    if consensus_parsed.valid_until < datetime.datetime.utcnow():
      print('cached consensus too old')
      os.remove('cache/consensus')
      return get_consensus()
  return consensus_parsed

def get_router_descriptor(router):
  filename = f'cache/routers/router-{router.name}-{router.ip}-{router.orport}'
  name,addr,fingerprint = random.choice(tor_dirs.auth_dirs)
  print(f'downloading router descriptor for {router.name} ({router.ip}:{router.orport}) from {name} ({addr})')
  router_response = requests.get(f'http://{addr}/tor/server/d/{router.descr_hash.hex()}')
  router_data = router_response.text
  print(f'response code {router_response.status_code}')
  with open(filename + '.txt', 'w') as f:
    f.write(router_data)
  router_doc = netdoc.parse_netdoc(router_data)
  router_parsed = routers.parse_router(router_doc)
  return router_parsed

class Circuit:
  def __init__(self, routers):
    self.conn = connect(routers[0].address())
    router_info = get_router_descriptor(routers[0])
    self.relays,self.circid = create_first_hop_ntor(self.conn, routers[0].id_hash, router_info.ntor_key)
    for router in routers[1:]:
      router_info = get_router_descriptor(router)
      self.relays = create_next_hop_ntor(self.conn, self.relays, self.circid, router.address(), router.id_hash, router_info.ntor_key)
  
  def send(self, cell, cell_type = RELAY): # a RelayCell
    # cell_type should be RELAY or RELAY_EARLY
    self.conn.send(self.relays.encrypt_forward(encode_relay_cell(self.circid, cell_type, cell)))
  
  def recv(self): # a RelayCell
    return decode_relay_cell(self.relays.decrypt_backward_from_end(self.conn.recv()))
  
  def destroy(self):
    # DESTROY cell with NONE (0x00) reason
    self.conn.send(Cell(self.circid, DESTROY, pad_fixed_length_data(b'\x00')))
