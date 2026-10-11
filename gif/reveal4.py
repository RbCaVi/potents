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

bits2 = []
def addbits2(n, count):
	bits2.extend(int(b) for b in f'{n:b}'.rjust(count, '0'))

gw,gh = gif.header.size
display = np.zeros((gh, gw), dtype = np.int64)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			ib = block
			(x,y),(w,h) = ib.pos, ib.size
			decoded = list(lzw.decompresslzwquick(block.initialcodesize + 1, lzw.unpacklzw(block.initialcodesize + 1, block.blocks.data)))
			pixels = np.array(decoded).reshape((h, w))
			displayarea = display[y:y + h, x:x + w]
			if gceb.hastransparent:
				cantransparent = (np.equal(pixels, displayarea) | np.equal(pixels, gceb.transparent)) & ~np.equal(displayarea, gceb.transparent) & np.less(displayarea, 1 << block.initialcodesize)
				left,top,right,bottom = 0, 0, 0, 0
				for row in cantransparent:
					if all(c == True for c in row):
						top += 1
					else:
						break
				for row in cantransparent[::-1]:
					if all(c == True for c in row):
						bottom += 1
					else:
						break
				for col in np.transpose(cantransparent):
					if all(c == True for c in col):
						left += 1
					else:
						break
				for col in np.transpose(cantransparent)[::-1]:
					if all(c == True for c in col):
						right += 1
					else:
						break
				
				x += left
				w -= left
				y += top
				h -= top
				w -= right
				h -= bottom
				print((left, right, top, bottom), (x, y, gw - (x + w), gh - (y + h)))

				left2 = 3 if x >= 3 else 0
				top2 = 3 if y >= 3 else 0
				right2 = 3 if gw - (x + w) >= 3 else 0
				bottom2 = 3 if gh - (y + h) >= 3 else 0
				print(((top2, bottom2), (left2, right2)))
				pixels2 = np.pad(pixels[top:pixels.shape[0] - bottom, left:pixels.shape[1] - right], ((top2, bottom2), (left2, right2)), constant_values = gceb.transparent)
				displayarea2 = display[y - top2:y + h + bottom2, x - left2:x + w + right2]
				cantransparent2 = (np.equal(pixels2, displayarea2) | np.equal(pixels2, gceb.transparent)) & ~np.equal(displayarea2, gceb.transparent) & np.less(displayarea2, 1 << block.initialcodesize)
				left2,top2,right2,bottom2 = 0, 0, 0, 0
				for row in cantransparent2:
					if all(c == True for c in row):
						top2 += 1
					else:
						break
				for row in cantransparent2[::-1]:
					if all(c == True for c in row):
						bottom2 += 1
					else:
						break
				for col in np.transpose(cantransparent2):
					if all(c == True for c in col):
						left2 += 1
					else:
						break
				for col in np.transpose(cantransparent2)[::-1]:
					if all(c == True for c in col):
						right2 += 1
					else:
						break

				if x >= 3 and left2 >= 3:
					addbits2(left, 2)
				if y >= 3 and top2 >= 3:
					addbits2(top, 2)
				if gw - (x + w) >= 3 and right2 >= 3:
					addbits2(right, 2)
				if gh - (y + h) >= 3 and bottom2 >= 3:
					addbits2(bottom, 2)

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

print(bits2)
fff = open('hidden2.txt', 'wb')
fff.write(bytes(int(''.join(x), 2) for x in itertools.batched(('01'[bit] for bit in bits2), 8)))
fff.close()

# errors moment
with open('hidden.txt', 'rb') as f1, open('lzw.py', 'rb') as f2:
	print([b1 - b2 for b1, b2 in itertools.zip_longest(f1.read(), f2.read(), fillvalue = 0) if b1 - b2 != 0])