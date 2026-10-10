import gif2
import lzw

# hide data in uh like accepted format things i guess
# comment and plaintext extension blocks
# application extension block
# all of this is nuked by discord

import struct
import time

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)

newblocks = []
for i,block in enumerate(gif.blocks):
	print(f'block {i}: ', end = '')
	begin = time.time()
	match block:
		case gif2.ApplicationExtensionBlock():
			# this does not conform to the spec - the first block should be 11 bytes
			block = gif2.RawExtensionBlock(0xFF, gif2.DataBlocks([gif2.DataBlock(struct.pack('<8s3s', block.appid, block.appauth) + b''.join(block.data for block in block.data) + b'hi guys i\'m secrets!')]))
		#case gif2.GraphicControlExtensionBlock():
		#	# this block must have exactly four bytes - some decoders reject it if it's not all one block - not very useful
		#	delay,hastransparent,transparent,disposal,userinput,reserved = block
		#	flags = gif2.packbits([1, 1, 3, 3], hastransparent, userinput, disposal, reserved)
		#	block = gif2.RawExtensionBlock(0xF9, gif2.DataBlocks([gif2.DataBlock(struct.pack('<BHB', flags, delay, transparent)[:3]), gif2.DataBlock(struct.pack('<BHB', flags, delay, transparent)[3:])]))
	newblocks.append(block)
	#match block:
	#	case gif2.ImageBlock():
	#		# this actually works
	#		newblocks.append(gif2.GraphicControlExtensionBlock(0, False, 0, 2, False, 0))
	#		newblocks.append(gif2.ImageBlock((0, 0), (1, 1), gif2.ColorTable([(0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 0)], 1, False), 0, False, 2, gif2.DataBlocks([gif2.DataBlock(lzw.packlzw(3, [4, 3, 5]) + b'grimy secrets')])))
	newblocks.append(gif2.CommentExtensionBlock(gif2.DataBlocks([gif2.DataBlock(b'hider <# heart 3 seventh')])))
	newblocks.append(gif2.PlaintextExtensionBlock((1, 1), (16, 16), (8, 8), 3, 4, [gif2.DataBlock(b'plehhh')]))
	#newblocks.append(gif2.RawExtensionBlock(0x71, gif2.DataBlocks([gif2.DataBlock(b'hi guys <<<33')]))) # kills dicord embeds
	print(f'{time.time() - begin:4f} seconds')

gif.blocks[:] = newblocks

with open('cupcake3.gif', 'wb') as f:
	gif2.GIF.write(f, gif)
