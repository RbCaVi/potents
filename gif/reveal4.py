import gif2
import lzw

import time
import itertools
import numpy as np
#C:\\Users\\bvh\\Downloads\\
with open('C:\\Users\\bvh\\Downloads\\cupcake5.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

bits = []
def addbits(n, count):
	bits.extend(int(b) for b in f'{n:b}'.rjust(count, '0'))

display = np.zeros(gif.header.size, dtype = np.int64)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			ib = block
			decoded = list(lzw.decompresslzwquick(block.initialcodesize + 1, lzw.unpacklzw(block.initialcodesize + 1, block.blocks.data)))
			pixels = np.array(decoded).reshape(block.size)
			if gceb.hastransparent:
				cantransparent = (np.equal(pixels, display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]]) | np.equal(pixels, gceb.transparent)) & ~np.equal(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], gceb.transparent) & np.less(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], 1 << block.initialcodesize)
				nontransparent = np.equal(pixels, display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]]) & ~np.equal(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], gceb.transparent) & np.less(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], 1 << block.initialcodesize)
				for b in np.extract(cantransparent, nontransparent):
					addbits(b, 1)
				np.copyto(display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]], pixels, where = ~np.equal(pixels, gceb.transparent))
			else:
				display[block.pos[0]:block.pos[0] + block.size[0], block.pos[1]:block.pos[1] + block.size[1]] = pixels
			#print(gceb)
			#print(ib._replace(blocks = None))
			'GraphicControlExtensionBlock', ['delay', 'hastransparent', 'transparent', 'disposal', 'userinput', 'reserved']
			'ImageBlock', ['pos', 'size', 'lct', 'reserved', 'interlaced', 'initialcodesize', 'blocks']
	print(f'{time.time() - begin:4f} seconds')

#print(bits)
#print(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits), 8)))
#print([int(bit == '1') for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in b'hi guys these fields are unused right?')])

fff = open('hidden.txt', 'wb')
fff.write(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits), 8)))
fff.close()