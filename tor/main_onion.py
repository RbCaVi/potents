import secrets
import random
import base64

import tor
import certificate
import lib

# test addresses
# l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion
# pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion
# sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion
# xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion
# gi3bsuc5ci2dr4xbh5b3kja5c6p5zk226ymgszzx7ngmjpc25tmnhaqd.onion

addr = 'gi3bsuc5ci2dr4xbh5b3kja5c6p5zk226ymgszzx7ngmjpc25tmnhaqd.onion'

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
  return certificate.ed_key(pubkey)

print(parse_onion(addr))

import sys
sys.exit()

cons = tor.get_consensus() # i can't call it 'consensus' because it'll collide with the module :(

router1 = random.choice([r for r in cons.routers if 'Guard' in r.flags])
router2 = random.choice([r for r in cons.routers])
router3 = random.choice([r for r in cons.routers if 'Exit' in r.flags])

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