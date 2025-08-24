import secrets
import random
import base64
import calendar
import time
import struct
import cryptography
import nacl
import bisect

import tor
import certificate
import lib

def parse_onion(onion_addr):
  assert onion_addr.endswith('.onion')
  data = base64.b32decode(onion_addr[:-6], casefold = True)
  assert len(data) == 32 + 2 + 1, 'onion address of wrong length'
  pubkey = lib.bytes_from(32, data)
  offset = 32
  checksum = lib.bytes_from(2, data, offset)
  offset += 2
  version = lib.bytes_from(1, data, offset)
  offset += 1
  assert version == b'\x03', 'unrecognized version'
  assert checksum == tor.sha3_256(b'.onion checksum' + pubkey + version)[:2], 'incorrect checksum'
  return cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(pubkey)

base_point = ( # i did not realize that this was the literal string
  b'(15112221349535400772501151409588531511454012693041857206046113283949847762202, '
  b'46316835694926478169428394003475163141307993866256225615783033603165251855960)'
)

def get_blinded_key(pub_key, period, period_length):
  # there is technically a secret between the public key and the base point,
  # but it's not used in original tor
  blinding_factor = tor.sha3_256(b'Derive temporary signing key\x00' + pub_key.public_bytes_raw() + base_point + b'key-blind' + struct.pack('>QQ', period, period_length))
  blinding_factor_key = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(blinding_factor)
  # not sure which of these is the correct one
  key1 = nacl.bindings.crypto_scalarmult_ed25519(blinding_factor, pub_key.public_bytes_raw())
  key2 = blinding_factor_key.exchange(pub_key)
  return key1 # try key2 as well if key1 doesn't work

def getperiod(curr_time, period_length):
  minutes = (curr_time + 1) // 60
  minutes -= 12 * 60 # 30 minute voting interval? * 12
  period = minutes // period_length
  return int(period)

consensus = tor.get_consensus()

curr_time = calendar.timegm(consensus.valid_after.timetuple())

period,period_length = getperiod(curr_time, 1440), 1440

# test addresses
# l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion
# pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion
# sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion
# xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion
# gi3bsuc5ci2dr4xbh5b3kja5c6p5zk226ymgszzx7ngmjpc25tmnhaqd.onion

addr = 'gi3bsuc5ci2dr4xbh5b3kja5c6p5zk226ymgszzx7ngmjpc25tmnhaqd.onion'

pub_key = parse_onion(addr)
blinded_key = get_blinded_key(pub_key, period, period_length)

hs_dirs = [r for r in consensus.routers if 'HSDir' in r.flags]

hs_replicas = 2 # number of separate ranges the descriptor is uploaded to (hsdir_n_replicas)
hs_spread = 3 # length of each range (hsdir_spread_fetch because i'm not uploading any)

hs_range_starts = [tor.sha3_256(b'store-at-idx' + blinded_key + struct.pack('>QQQ', i, period_length, period)) for i in range(1, hs_replicas + 1)]
hs_dir_indices = sorted([(tor.sha3_256(b'node-idx' + bytes(tor.get_router_descriptor(r).id25519.exts[4]) + consensus.srv_curr + struct.pack('>QQ', period, period_length)), r) for r in hs_dirs])

selected_hs_dirs = []

for start in hs_range_starts:
  index = bisect.bisect(hs_dir_indices, (start, None)) + 1
  for i in range(hs_spread):
    while True:
      index += 1
      if index >= len(hs_dirs):
        index = 0
      if hs_dir_indices[index][1] not in selected_hs_dirs:
        selected_hs_dirs.append(hs_dir_indices[index][1])
        break

router1 = random.choice([r for r in consensus.routers if 'Guard' in r.flags])
router2 = random.choice([r for r in consensus.routers])
router3 = random.choice(selected_hs_dirs)

path_routers = [router1, router2, router3]

print('routers:')
for router in path_routers:
  print(f'  {router.name} at {router.address()}')

circuit = tor.Circuit(path_routers)

streamid = secrets.randbits(16)

circuit.send(tor.encode_relay_begin_cell(streamid, 'www.example.com:80'))

resp = circuit.recv()

if resp.command == tor.CONNECTED:
  addr,ttl = tor.decode_relay_connected_cell(resp)
  print(addr, ttl)
else:
  print(resp)

assert resp.command == tor.CONNECTED

circuit.send(tor.encode_relay_data_cell(streamid, b'GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n'))

recieved = b''

while True:
  cell = circuit.recv()
  if cell.command == tor.END:
    break
  elif cell.command == tor.DATA:
    recieved += cell.payload
    print(recieved.decode('utf-8'))
    if b'\r\n\r\n' in recieved:
      header,body = recieved.split(b'\r\n\r\n', 1)
      respline,*headerlines = header.split(b'\r\n')
      headers = {field.lower():value.strip() for field,value in [l.split(b':', 1) for l in headerlines]}
      if b'content-length' in headers and len(body) >= int(headers[b'content-length']):
        break
  else:
    print(cell)

print(headers)
print(body.decode('utf-8'))

circuit.destroy()