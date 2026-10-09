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
			print(f'({block.size for block in blocks.blocks[:-1]} bytes) ', end = '')
			data1,data2 = extractdata(block.blocks, block.initialcodesize)
			hiddendata.append(data1)
			hiddendata2.append(data2)
	print(f'{time.time() - begin:4f} seconds')

while hiddendata[-1][-1] == 255:
	hiddendata[-1] = hiddendata[-1][:-1]
	if hiddendata[-1] == b'':
		hiddendata = hiddendata[:-1]

print(hiddendata)