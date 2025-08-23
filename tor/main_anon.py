import secrets
import random

import tor

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