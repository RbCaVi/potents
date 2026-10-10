import gif2
import lzw

import time
import itertools
#C:\\Users\\bvh\\Downloads\\
with open('cupcake4.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

bits = []
def addbits(n, count):
	bits.extend(int(b) for b in f'{n:b}'.rjust(count, '0'))

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			ib = block
			print(gceb)
			print(ib._replace(blocks = None))
			addbits(gceb.userinput, 1)
			addbits(gceb.reserved, 3)
			addbits(ib.lct.size, 3)
			addbits(ib.lct.sorted, 1)
			addbits(ib.reserved, 2)
			addbits(ib.interlaced, 1)
			'ImageBlock', ['pos', 'size', 'lct', 'reserved', 'interlaced', 'initialcodesize', 'blocks']
			'GraphicControlExtensionBlock', ['delay', 'hastransparent', 'transparent', 'disposal', 'userinput', 'reserved']
	print(f'{time.time() - begin:4f} seconds')

print(bits)
print(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits), 8)))
print([int(bit == '1') for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in b'hi guys these fields are unused right?')])