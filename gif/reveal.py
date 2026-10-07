import gif2

import io

with open('C:/Users/bvh/Downloads/cupcake2/cupcake2.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

hiddendata = []

def extractdata(blocks):
	return bytes(block.size for block in blocks.blocks[:-1])

for block in gif.blocks:
	match block:
		case gif2.ImageBlock():
			hiddendata.append(extractdata(block.blocks))

while hiddendata[-1][-1] == 255:
	hiddendata[-1] = hiddendata[-1][:-1]
	if hiddendata[-1] == b'':
		hiddendata = hiddendata[:-1]

print(hiddendata)