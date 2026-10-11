import gif2
import lzw

import itertools
import time

import numpy as np
import PIL.Image

# hide data in image data
# image data overflow is nuked by discord
# image data underflow is not even recognized by discord's gif recoder
# redundant pixels are nuked by discord (mostly? idk)
# frame positioning is nuked by discord

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

datastream2 = (bit == '1' for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in open('conceal4.py', 'rb').read()))
def getbits2(count):
	n = 0
	for i in range(count):
		n <<= 1
		n += next(datastream2, 0)
	return n

gw,gh = gif.header.size
display = np.full((gh, gw), 256, dtype = np.int64)
colors = np.array(gif.header.gct.colors)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			assert isinstance(gif.blocks[i - 1], gif2.GraphicControlExtensionBlock)
			gceb = gif.blocks[i - 1]
			(x,y),(w,h) = block.pos, block.size
			pixels = np.array(block.decoded).reshape((h, w))
			displayarea = display[y:y + h, x:x + w]
			print(1 << block.initialcodesize - 1, max(pixels.flatten()), '', end = '')
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
				# left right top bottom are < 0 here
				print('jj', (h, w), pixels.shape)
				pixels = pixels[top:pixels.shape[0] - bottom, left:pixels.shape[1] - right]
				cantransparent = cantransparent[top:cantransparent.shape[0] - bottom, left:cantransparent.shape[1] - right]
				print((left, right, top, bottom), pixels.shape, cantransparent.shape)
				print('AAA                   ', (left, right, top, bottom), (x, y, gw - (x + w), gh - (y + h)))

				left2 = 3 if x >= 3 else 0
				top2 = 3 if y >= 3 else 0
				right2 = 3 if gw - (x + w) >= 3 else 0
				bottom2 = 3 if gh - (y + h) >= 3 else 0
				pixels2 = np.pad(pixels, ((top2, bottom2), (left2, right2)), constant_values = gceb.transparent)
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

				left,top,right,bottom = 0, 0, 0, 0
				if x >= 3 and left2 >= 3:
					left = getbits2(2)
				if y >= 3 and top2 >= 3:
					top = getbits2(2)
				if gw - (x + w) >= 3 and right2 >= 3:
					right = getbits2(2)
				if gh - (y + h) >= 3 and bottom2 >= 3:
					bottom = getbits2(2)

				print('a', (h, w), pixels.shape)
				x -= left
				w += left
				y -= top
				h += top
				w += right
				h += bottom

				print((left, right, top, bottom), (x, y, gw - (x + w), gh - (y + h)))

				pixels = np.pad(pixels, ((top, bottom), (left, right)), constant_values = gceb.transparent)
				cantransparent = np.pad(cantransparent, ((top, bottom), (left, right)), constant_values = True)

				print('b', (h, w), pixels.shape)

				nontransparent = np.zeros_like(cantransparent)
				np.place(nontransparent, cantransparent, [getbits(1) == 1 for _ in range(sum(sum(cantransparent)))])
				np.copyto(pixels, gceb.transparent, where = cantransparent & ~nontransparent)

				block = block._replace(pos = (x, y), size = (w, h))
				displayarea = display[y:y + h, x:x + w]
				print(displayarea.shape, (h, w))
				np.copyto(pixels, displayarea, where = nontransparent)
				np.copyto(displayarea, pixels, where = ~np.equal(pixels, gceb.transparent))
			else:
				displayarea[:] = pixels
			PIL.Image.fromarray(np.uint8(colors[display])).save(f'out/block{i}.png')
			gif.blocks[i - 1] = gif.blocks[i - 1]._replace()
			gif.blocks[i] = block._replace(blocks = packblocks(lzw.packlzw(block.initialcodesize + 1, lzw.compresslzw(block.initialcodesize + 1, [int(x) for x in pixels.flatten()], choose))))
	print(f'{time.time() - begin:4f} seconds')

print([*datastream])

with open('cupcake5.gif', 'wb') as f:
	gif2.GIF.write(f, gif)