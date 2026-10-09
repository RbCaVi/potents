import gif2
import lzw

import itertools
import time

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

ff = open('output4.txt', 'w')

hiddendata2 = []

def recompressblocks(blocks, initialcodesize, groupdatastream, lzwdatastream):
	data = blocks.data
	codes = lzw.unpacklzw(initialcodesize + 1, blocks.data)
	items = lzw.decompresslzwquick(initialcodesize + 1, codes)
	def choose(comlength):
		if comlength == 1:
			i = 0
		elif comlength == 2:
			i = 0
		elif comlength < 8:
			i = comlength - 1
		else:
			value = 1
			n = 0
			while True:
				if n + value >= comlength:
					break
				n += value * next(lzwdatastream, 0)
				value *= 2
			# index 1 is always RESET
			i = comlength - 1 - n
		print(i, comlength, file = ff)
		hiddendata2.append((i, comlength))
		return i
	codes = lzw.compresslzw(initialcodesize + 1, items, choose)
	data = lzw.packlzw(initialcodesize + 1, codes)
	i = 0
	blocks = []
	while len(data) - i > 255:
		byte = next(groupdatastream, 255)
		blocks.append(gif2.DataBlock(data[i:i + byte]))
		i += byte
	blocks.append(gif2.DataBlock(data[i:]))
	return gif2.DataBlocks(blocks)

groupdatastream = iter(bytes('The FitnessGram Pacer Test is a multistage aerobic capacity test that progressively gets more difficult as it continues. The 20 meter pacer test will begin in 30 seconds. Line up at the start. The running speed starts slowly but gets faster each minute after you hear this signal bodeboop. A sing lap should be completed every time you hear this sound. ding Remember to run in a straight line and run as long as possible. The second time you fail to complete a lap before the sound, your test is over. The test will begin on the word start. On your mark. Get ready!... Start. ding', 'utf-8'))
lzwdatastream = (bit == '1' for bit in itertools.chain.from_iterable(f'{b:>08b}' for b in open('conceal.py', 'rb').read()))

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			gif.blocks[i] = block._replace(blocks = recompressblocks(block.blocks, block.initialcodesize, groupdatastream, lzwdatastream))
	print(f'{time.time() - begin:4f} seconds')

with open('cupcake2.gif', 'wb') as f:
	gif2.GIF.write(f, gif)

print([*groupdatastream])
print([*lzwdatastream])

import pickle
with open('hiddendata2.pkl', 'wb') as f:
	pickle.dump(hiddendata2, f)