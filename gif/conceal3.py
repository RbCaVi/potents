import gif2
import lzw

import itertools
import time

# hide data in unused fields
# nuked by discord

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

datastream = (bit == '1' for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in b'hi guys these fields are unused right?'))
def getbits(count):
	n = 0
	for i in range(count):
		n <<= 1
		n += next(datastream, 0)
	return n

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gif.blocks[i - 1] = gif.blocks[i - 1]._replace(userinput = getbits(1), reserved = getbits(3))
			gif.blocks[i] = block._replace(lct = block.lct._replace(size = getbits(3), sorted = getbits(1)), reserved = getbits(2), interlaced = getbits(1))
	print(f'{time.time() - begin:4f} seconds')

print([*datastream])

with open('cupcake4.gif', 'wb') as f:
	gif2.GIF.write(f, gif)