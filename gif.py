with open('cupcake.gif', 'rb') as f:
  data = f.read()

import struct

class DataSlice:
  # a slice of bytes
  # represented as a buffer and an offset
  
  def __init__(self, buf):
    self.buf = buf
    self.offset = 0
  
  def unpackbytes(self, n):
    # returns the first n bytes
    # and advances the offset
    data = self.buf[self.offset:self.offset + n]
    self.offset += n
    return data
  
  def unpackstruct(self, fmt):
    # decode a chunk using the struct package
    data = struct.unpack_from(fmt, self.buf, self.offset)
    self.offset += struct.calcsize(fmt)
    return data
  
  def unpackbyte(self):
    # returns the first byte as an integer
    return self.unpackbytes(1)[0]

data = DataSlice(data)

assert data.unpackbytes(3) == b'GIF'

def assertp(x, predicate):
  assert predicate(x)
  return x

version = assertp(data.unpackbytes(3), lambda x: x in [b'87a', b'89a'])
print('version', version)

w,h,flags,bgcol,aspect = data.unpackstruct('<HHBBB')
print('size', w, h)
print('aspect', aspect)

def asbits(n, bits):
  top = 2 ** bits
  assert n >= 0 and n < top, n
  return bin(top + n)[3:]

def asbit(b):
  assert b in [True, False]
  return '1' if b else '0'

def frombits(bits):
  return int(bits, 2)

def frombit(bit):
  return bit == '1'

flags = asbits(flags, 8)
hasgct = frombit(flags[0:1])
colorbits = frombits(flags[1:4])
gctsorted = frombit(flags[4:5])
gctbits = frombits(flags[5:8])

print('colorsize 2 ^', colorbits + 1)

def hexcomponent(n):
  assert n >= 0 and n < 256
  return hex(256 + n)[3:]

def hexcolor(c):
  r,g,b = c
  return '#' + hexcomponent(r) + hexcomponent(g) + hexcomponent(b)

# print out a color table in rows of 16
def printcolortablehex(table):
  w = min(len(table), 16)
  h = (len(table) + 15) // 16
  
  for i in range(h):
    print(' '.join(hexcolor(c) for c in table[16 * i:16 * (i + 1)]))

# use pillow to show the color table
# 16 colors in a row
# each color is a 30x30 square
def showcolortable(table):
  w = min(len(table), 16)
  h = (len(table) + 15) // 16
  
  PIL.Image.fromarray(numpy.reshape(table, (w, h, 3)).astype(numpy.uint8)).resize((w * 30, h * 30), PIL.Image.Resampling.NEAREST).show()

import PIL.Image
import numpy

def unpackcolortable(data, tablebits):
  tablesize = 2 ** (tablebits + 1)
  tabledata = data.unpackbytes(3 * tablesize)
  table = [*struct.iter_unpack('<BBB', tabledata)]
  return table

if hasgct:
  gct = unpackcolortable(data, gctbits)
  
  #print('gct')
  #print('sorted:', gctsorted)
  #print('bgidx:', bgcol)
  #printcolortablehex(gct)
  #showcolortable(gct)
else:
  gct = None
  
  #print('no global color table')

def unpackblocks(data):
  out = b''
  while True:
    chunk = data.unpackbytes(data.unpackbyte())
    out += chunk
    if len(chunk) == 0:
      break
  return out

def unpackextension(data):
  return ['ext', data.unpackbyte(), unpackblocks(data)]

def unpackimdesc(data):
  left,top,w,h,flags = data.unpackstruct('<HHHHB')
  
  flags = asbits(flags, 8)
  haslct = frombit(flags[0:1])
  interlace = frombit(flags[1:2])
  lctsorted = frombit(flags[2:3])
  #reserved = frombits(flags[3:5]) # should be 0
  lctbits = frombits(flags[5:8])
  
  if haslct:
    lct = unpackcolortable(data, lctbits)
  else:
    lct = None
  
  lzwcodesize = data.unpackbyte()
  lzwencoded = unpackblocks(data)
  
  return ['img', (left, top, w, h), interlace, lct, lctsorted, lzwcodesize, lzwencoded]

blocks = []
while True:
  btype = data.unpackbyte()
  if btype == 0x21: # extension
    blocks.append(unpackextension(data))
  elif btype == 0x2C: # image descriptor
    blocks.append(unpackimdesc(data))
  elif btype == 0x3B: # end
    assert data.offset == len(data.buf)
    break
  else:
    data.offset -= 1
    print(data.buf[data.offset:][:100])
    assert False, f'unrecognized leading byte {btype}'

# return an iterator of symbols
def lzwsymbols(data, symbolsize):
  print('s', symbolsize)
  back = 0
  n = 0
  mask = 2 ** symbolsize - 1
  osymbolsize = symbolsize
  clear = 2 ** (symbolsize - 1)
  end = clear + 1
  dictsize = end
  while True:
    dictsize += 1
    while back < symbolsize:
      n |= data.unpackbyte() << back
      back += 8
    symbol = n & mask
    n >>= symbolsize
    back -= symbolsize
    # i have no idea what this should be
    # it increments the size when the dictionary overflows
    if dictsize == mask + 1 and symbolsize < 12: # it is the maximum value
      #print('increment symbol size after', dictsize, 'symbols')
      symbolsize += 1
      mask = 2 ** symbolsize - 1
    #if symbol == end:
      #print('end at', data.offset, 'of', len(data.buf), 'after', dictsize, 'symbols')
    yield symbol
    if symbol == clear:
      #print('clear at', count, 'symbols')
      symbolsize = osymbolsize
      mask = 2 ** symbolsize - 1
      dictsize = end
    if symbol == end:
      break




def lzwdecompress(data, symbolsize):
  clear = 2 ** (symbolsize)
  end = clear + 1
  for symbol in lzwsymbols(DataSlice(data), symbolsize + 1):
    if symbol == clear:
      # i'm assuming that the first symbol is a clear symbol
      # it's required by the spec
      nextsymbol = 2 ** symbolsize + 2
      dictionary = [[i] if i < 2 ** symbolsize else None for i in range(4096)]
      last = None
      continue
    if symbol == end:
      break
    if last is not None:
      # add a new symbol to the dictionary
      if symbol == nextsymbol:
        nextchar = dictionary[last][0]
      else:
        nextchar = dictionary[symbol][0]
      dictionary[nextsymbol] = dictionary[last] + [nextchar]
      #print('adding', dictionary[nextsymbol])
      nextsymbol += 1
    last = symbol
    yield from dictionary[symbol]

seenapplicationblock = False
comments = []
c = 1
for block in blocks:
  if block[0] == 'ext':
    _,blocktype,blockdata = block
    if blocktype == 0xFE: # comment
      comments.append(block[2])
      continue
    elif blocktype == 0xFF: # application
      # i don't know what this should be
      # i know b'NETSCAPE2.0'
      # which i guess means an animated gif? the kind from tenor?
      # https://stackoverflow.com/a/28486261
      print(blockdata)
      aid = blockdata[0:8] # application id
      aac = blockdata[8:11] # and authentication code
      print('application id', aid, aac)
      blockdata = blockdata[11:]
      if aid == b'NETSCAPE':
        assert aac == b'2.0'
        bid,loopcount = struct.unpack('<BH', blockdata)
        assert bid == 1
        #print('loop count:', loopcount)
      else:
        assert False, f'unrecognized application: {aid}'
    elif blocktype == 0xF9: # graphical control
      flags,delay,transp = struct.unpack('<BHB', blockdata)
      flags = asbits(flags, 8)
      #reserved = frombits(flags[0:3]) # should be 0
      disposal = frombits(flags[3:6])
      userinput = frombit(flags[6:7])
      transparent = frombit(flags[7:8])
      print(disposal, userinput, transparent, delay, transp)
      if not transparent:
        transp = 256
    else:
      # 0x01 for plain text display - section 25
      assert False, f'unrecognized extension id: {block[1]}'
  elif block[0] == 'img':
    #print(block[:-1], ' '.join(bin(n + 256)[3:][::-1] for n in block[-1][:20]))
    w,h = block[1][2], block[1][3]
    imarr = numpy.reshape([*lzwdecompress(block[-1], block[-2])], (h, w)).astype(numpy.uint8)
    im = PIL.Image.fromarray(imarr)
    im.putalpha(PIL.Image.fromarray(imarr != transp))
    im.putpalette(sum(gct, ()))
    im.convert('RGBA').save(f'out/frame{c}.png')
    c += 1
  else:
    assert False, f'unrecognized block type: {block[0]}'