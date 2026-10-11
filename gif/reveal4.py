import gif2
import lzw

import time
import itertools
import numpy as np
#C:\\Users\\bvh\\Downloads\\
with open('cupcake5.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

bits = []
def addbits(n, count):
	bits.extend(int(b) for b in f'{n:b}'.rjust(count, '0'))

display = np.zeros(gif.header.size[::-1], dtype = np.int64)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			ib = block
			decoded = list(lzw.decompresslzwquick(block.initialcodesize + 1, lzw.unpacklzw(block.initialcodesize + 1, block.blocks.data)))
			pixels = np.array(decoded).reshape(block.size[::-1])
			displayarea = display[block.pos[1]:block.pos[1] + block.size[1], block.pos[0]:block.pos[0] + block.size[0]]
			if gceb.hastransparent:
				cantransparent = (np.equal(pixels, displayarea) | np.equal(pixels, gceb.transparent)) & ~np.equal(displayarea, gceb.transparent) & np.less(displayarea, 1 << block.initialcodesize)
				nontransparent = cantransparent & ~np.equal(pixels, gceb.transparent)
				for b in np.extract(cantransparent, nontransparent):
					addbits(b, 1)
				np.copyto(displayarea, pixels, where = ~np.equal(pixels, gceb.transparent))
			else:
				displayarea[:] = pixels
			#print(gceb)
			#print(ib._replace(blocks = None))
			print(f'{gceb.disposal} ', end = '')
			'GraphicControlExtensionBlock', ['delay', 'hastransparent', 'transparent', 'disposal', 'userinput', 'reserved']
			'ImageBlock', ['pos', 'size', 'lct', 'reserved', 'interlaced', 'initialcodesize', 'blocks']
	print(f'{time.time() - begin:4f} seconds')

#print(bits)
#print(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits), 8)))
#print([int(bit == '1') for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in b'hi guys these fields are unused right?')])

fff = open('hidden.txt', 'wb')
fff.write(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits), 8)))
fff.close()

# errors moment
with open('hidden.txt', 'rb') as f1, open('lzw.py', 'rb') as f2:
	print([b1 - b2 for b1, b2 in itertools.zip_longest(f1.read(), f2.read(), fillvalue = 0) if b1 - b2 != 0])