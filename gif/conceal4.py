import gif2
import lzw

import itertools
import time

import numpy as np
import PIL.Image

# hide data in image data
# overflow is nuked

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			block.decoded = list(lzw.decompresslzwquick(block.initialcodesize + 1, lzw.unpacklzw(block.initialcodesize + 1, block.blocks.data)))
	print(f'{time.time() - begin:4f} seconds')

def packblocks(data):
	blocks = []
	for i in range(0, len(data), 255):
		blocks.append(gif2.DataBlock(data[i:i + 255]))
	blocks.append(gif2.DataBlock(data[i:]))
	return gif2.DataBlocks(blocks)

resetcounter = itertools.cycle(range(4096))
next(resetcounter)
def choose(comlength):
	counter = next(resetcounter)
	#print('a', i, comlength, counter)
	if comlength == 1:
		return 0
	if counter == 0:
		#print('RESET')
		return 1
	if comlength < 3:
		return 0
	return comlength - 1

datastream = (bit == '1' for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in open('lzw.py', 'rb').read()))
def getbits(count):
	n = 0
	for i in range(count):
		n <<= 1
		n += next(datastream, 0)
	return n

display = np.zeros(gif.header.size, dtype = np.int64)
colors = np.array(gif.header.gct.colors)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			pixels = np.array(block.decoded).reshape(block.size)
			print(1 << block.initialcodesize - 1, max(pixels.flatten()), '', end = '')
			if gceb.hastransparent:
				cantransparent = (np.equal(pixels, display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]]) | np.equal(pixels, gceb.transparent)) & ~np.equal(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], gceb.transparent) & np.less(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], 1 << block.initialcodesize)
				np.place(cantransparent, cantransparent, [getbits(1) == 1 for _ in range(sum(sum(cantransparent)))])
				np.copyto(pixels, display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], where = cantransparent)
				np.copyto(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], pixels, where = ~np.equal(pixels, gceb.transparent))
			else:
				display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]] = pixels
			PIL.Image.fromarray(np.uint8(colors[display])).save(f'out/block{i}.png')
			gif.blocks[i - 1] = gif.blocks[i - 1]._replace()
			gif.blocks[i] = block._replace(size = (block.size[0], block.size[1]), pos = (block.pos[0], block.pos[1]), blocks = packblocks(lzw.packlzw(block.initialcodesize + 1, lzw.compresslzw(block.initialcodesize + 1, [int(x) for x in pixels.flatten()], choose))))
	print(f'{time.time() - begin:4f} seconds')

print([*datastream])

with open('cupcake5.gif', 'wb') as f:
	gif2.GIF.write(f, gif)