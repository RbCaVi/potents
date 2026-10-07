import gif2

import io

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

def regroupblocks(blocks, datastream):
	data = blocks.data
	i = 0
	blocks = []
	while len(data) - i > 255:
		byte = next(datastream, 255)
		blocks.append(gif2.DataBlock(data[i:i + byte]))
		i += byte
	blocks.append(gif2.DataBlock(data[i:]))
	return gif2.DataBlocks(blocks)

datastream = iter(bytes('hi cheese its', 'utf-8'))

for i,block in enumerate(gif.blocks):
	match block:
		case gif2.ImageBlock():
			gif.blocks[i] = block._replace(blocks = regroupblocks(block.blocks, datastream))

with open('cupcake2.gif', 'wb') as f:
	gif2.GIF.write(f, gif)