import gif2
import lzw

import time
import itertools
#C:\\Users\\bvh\\Downloads\\
with open('C:\\Users\\bvh\\Downloads\\cupcake3.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.RawExtensionBlock():
			print(block.blocks)
		case gif2.ApplicationExtensionBlock():
			print(block.data)
		case gif2.CommentExtensionBlock():
			print(block.data)
		case gif2.PlaintextExtensionBlock():
			print(block)
		case gif2.ImageBlock():
			if len(block.blocks.data) < 400:
				print(block.blocks.data)
	print(f'{time.time() - begin:4f} seconds')