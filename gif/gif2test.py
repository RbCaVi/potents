import gif2

import io
import lzw
import time

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

def repackblocks(blocks, initialcodesize):
	codes = lzw.unpacklzw(initialcodesize + 1, blocks.data)
	choices = []
	items = list(lzw.decompresslzw(initialcodesize + 1, codes, lambda index, length: choices.append((index, length))))
	def choose(comlength):
		index,declength = choices.pop(0)
		assert comlength == declength, f'{comlength}, {declength}'
		return index
	codes = lzw.compresslzw(initialcodesize + 1, items, choose)
	data = lzw.packlzw(initialcodesize + 1, codes)
	i = 0
	blocks = []
	while len(data) - i > 255:
		blocks.append(gif2.DataBlock(data[i:i + 255]))
		i += 255
	blocks.append(gif2.DataBlock(data[i:]))
	return gif2.DataBlocks(blocks)

print(f'{len(gif.blocks)} blocks')
for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ImageBlock():
			gif.blocks[i] = block._replace(blocks = repackblocks(block.blocks, block.initialcodesize))
	print(f'{time.time() - begin} seconds:4f')

with io.BytesIO() as f:
	gif2.GIF.write(f, gif)
	f.seek(0)
	data2 = f.read()

print(len(data1), len(data2))

for i in range(0, len(data1), 16):
	chunk1 = data1[i:i + 16]
	chunk2 = data2[i:i + 16]
	if chunk1 != chunk2:
		print(i)
		print(chunk1.hex())
		print(chunk2.hex())
		input()