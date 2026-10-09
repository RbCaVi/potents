import gif2
import lzw

import time

with open('cupcake2.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

hiddendata = []
hiddendata2 = []

def extractdata(blocks, initialcodesize):
	data1 = bytes(block.size for block in blocks.blocks[:-1])
	codes = lzw.unpacklzw(initialcodesize + 1, blocks.data)
	data2 = []
	list(lzw.decompresslzw(initialcodesize + 1, codes, lambda index, length: data2.append((index, length))))
	return data1, data2

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			print(f'({sum(block.size for block in block.blocks.blocks[:-1])} bytes) ', end = '')
			data1,data2 = extractdata(block.blocks, block.initialcodesize)
			hiddendata.append(data1)
			hiddendata2.append(data2)
	print(f'{time.time() - begin:4f} seconds')

while hiddendata[-1][-1] == 255:
	hiddendata[-1] = hiddendata[-1][:-1]
	if hiddendata[-1] == b'':
		hiddendata = hiddendata[:-1]

print(hiddendata)

bits = []
for index,length in hiddendata2:
	if length < 8:
		continue
	value = 1
	for bit in f'{index:b}'.rjust(20)[::-1]:
		if n + value >= length:
			break
		n += value * (bit == 1)
		bits.append(bit)
		value *= 2

print(bits)