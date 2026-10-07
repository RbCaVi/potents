import collections
import struct

def readstruct(fmt, f):
	return struct.unpack(fmt, f.read(struct.calcsize(fmt)))

def writestruct(fmt, f, *items):
	f.write(struct.pack(fmt, *items))

def unpackbits(fieldsizes, bits):
	items = []
	for fieldsize in fieldsizes:
		mask = (1 << fieldsize) - 1
		items.append(bits & mask)
		bits >>= fieldsize
	return items

def packbits(fieldsizes, *items):
	bits = 0
	for fieldsize,item in reversed(list(zip(fieldsizes, items))):
		assert item >> fieldsize == 0
		bits <<= fieldsize
		bits |= item
	return bits

class ColorTable(collections.namedtuple('ColorTable', ['colors', 'size', 'sorted'])):
	pass

def readcolors(bits, f):
	size = 1 << (bits + 1)
	data = f.read(size * 3) # 3 bytes per color
	return list(struct.iter_unpack('<BBB', data)) # red, green, blue

def writecolors(bits, f, colors):
	size = 1 << (bits + 1)
	assert len(colors) == size
	f.write(b''.join(struct.pack('<BBB', *color) for color in colors))

class GIFHeader(collections.namedtuple('GIFHeader', ['version', 'size', 'gct', 'colorres', 'bgcolor', 'pxaspect'])):
	@property
	def aspect(self):
		return None if self.pxaspect == 0 else (self.pxaspect + 15) / 64

	@staticmethod
	def read(f):
		assert f.read(3) == b'GIF'
		version = f.read(3)
		width,height,flags,bgcolor,pxaspect = readstruct('<HHBBB', f)

		assert version in [b'87a', b'89a']
		gctsizebits,gctsorted,colorres,hasgct = unpackbits([3, 1, 3, 1], flags)

		# bgcolor is the index in the GCT (global color table) for a background color (if the GCT is present)
		# pxaspect determines the pixel aspect ratio
		#   either 0 - not given
		#   or width/height = (pxaspect + 15) / 64
		# gctsizebits is the log2 of the number of colors in the GCT, minus 1
		# gctsorted is supposed to mean "the colors in the GCT are in order of decreasing importance"
		# colorres is supposed to be the source color resolution of the gif
		# hasgct indicates if the GCT is present

		if hasgct:
			gct = readcolors(gctsizebits, f)
		else:
			gct = None

		return GIFHeader(version, (width, height), ColorTable(gct, gctsizebits, gctsorted), colorres, bgcolor, pxaspect)

	@staticmethod
	def write(f, header):
		version,(width,height),(gct,gctsizebits,gctsorted),colorres,bgcolor,pxaspect = header
		hasgct = gct is not None
		flags = packbits([3, 1, 3, 1], gctsizebits, gctsorted, colorres, hasgct)

		f.write(b'GIF')
		f.write(version)
		writestruct('<HHBBB', f, width, height, flags, bgcolor, pxaspect)

		if hasgct:
			writecolors(gctsizebits, f, gct)

class EndBlock(collections.namedtuple('EndBlock', [])):
	pass

class ImageBlock(collections.namedtuple('ImageBlock', ['pos', 'size', 'lct', 'reserved', 'interlaced', 'initialcodesize', 'blocks'])):
	@staticmethod
	def read(f):
		x,y,width,height,flags = readstruct('<HHHHB', f)
		# x, y, width, and height are the dimensions of this image frame
		lctsizebits,reserved,lctsorted,interlaced,haslct = unpackbits([3, 2, 1, 1, 1], flags)
		# lctsizebits is the log2 of the number of colors in the LCT, minus 1
		# lctsorted is supposed to mean "the colors in the LCT are in order of decreasing importance"
		# interlaced indicates if this frame is interlaced - by rows [0::8], [4::8], [2::4], [1::2]
		# haslct indicates if the LCT is present

		if haslct:
			lct = readcolors(lctsizebits, f)
		else:
			lct = None

		lzwcodesize, = readstruct('<B', f)
		blocks = DataBlocks.read(f)

		return ImageBlock((x, y), (width, height), ColorTable(lct, lctsizebits, lctsorted), reserved, interlaced, lzwcodesize, blocks)

	@staticmethod
	def write(f, image):
		(x,y),(width,height),(lct,lctsizebits,lctsorted),reserved,interlaced,lzwcodesize,blocks = image
		haslct = lct is not None
		flags = packbits([3, 2, 1, 1, 1], lctsizebits, reserved, lctsorted, interlaced, haslct)

		writestruct('<HHHHB', f, x, y, width, height, flags)

		if haslct:
			writecolors(lctsizebits, f, lct)

		writestruct('<B', f, lzwcodesize)
		DataBlocks.write(f, blocks)

class DataBlock(collections.namedtuple('DataBlock', ['data'])):
	@property
	def size(self):
		return len(self.data)

	@staticmethod
	def read(f):
		blocksize, = readstruct('<B', f)
		data = f.read(blocksize)
		return DataBlock(data)

	@staticmethod
	def write(f, block):
		data, = block
		writestruct('<B', f, block.size)
		f.write(data)

class CommentExtensionBlock(collections.namedtuple('CommentExtensionBlock', ['data'])):
	@staticmethod
	def read(f):
		blocks = DataBlocks.read(f)
		return CommentExtensionBlock(blocks)

	@staticmethod
	def write(f, block):
		blocks, = block
		DataBlocks.write(f, blocks)

class ApplicationExtensionBlock(collections.namedtuple('ApplicationExtensionBlock', ['appid', 'appauth', 'data'])):
	@staticmethod
	def read(f):
		idblock,*blocks = DataBlocks.read(f).blocks
		# not sure if the first block is required to have exactly 11 bytes
		appid,appauth = struct.unpack('<8s3s', idblock.data)
		# appid is the "application identifier" - usually 'NETSCAPE' for animated gifs
		# appauth is an "application authentication code" - usually '2.0' for animated gifs
		return ApplicationExtensionBlock(appid, appauth, blocks)

	@staticmethod
	def write(f, block):
		appid,appauth,blocks = block
		blocks.insert(0, DataBlock(struct.pack('<8s3s', appid, appauth)))
		DataBlocks.write(f, DataBlocks(blocks))

class GraphicControlExtensionBlock(collections.namedtuple('GraphicControlExtensionBlock', ['delay', 'hastransparent', 'transparent', 'disposal', 'userinput', 'reserved'])):
	@staticmethod
	def read(f):
		# not sure if only one block is allowed
		datablock, = DataBlocks.read(f).blocks
		# not sure if the first block is required to have exactly 4 bytes
		flags,delay,transparent = struct.unpack('<BHB', datablock.data)
		hastransparent,userinput,disposal,reserved = unpackbits([1, 1, 3, 3], flags)
		# delay is the time the frame is shown before advancing to the next frame, in 1/100 second
		# transparent is the color index that is replaced with transparency
		# hastransparent is if transparent is active
		# userinput is supposed to mean wait for user input before advancing
		# disposal determines what happens to the frame when the next frame is rendered
		#   0 - unspecified
		#   1 - leave frame
		#   2 - restore to background
		#   3 - restore to previous content
		#   4-7 are undefined
		return GraphicControlExtensionBlock(delay, hastransparent, transparent, disposal, userinput, reserved)

	@staticmethod
	def write(f, block):
		delay,hastransparent,transparent,disposal,userinput,reserved = block
		flags = packbits([1, 1, 3, 3], hastransparent, userinput, disposal, reserved)
		DataBlocks.write(f, DataBlocks([DataBlock(struct.pack('<BHB', flags, delay, transparent))]))

class PlaintextExtensionBlock(collections.namedtuple('PlaintextExtensionBlock', ['pos', 'gridsize', 'charsize', 'fg', 'bg', 'blocks'])):
	@staticmethod
	def read(f):
		datablock,*blocks = DataBlocks.read(f)
		# not sure if the first block is required to have exactly 12 bytes
		x,y,gridwidth,gridheight,charwidth,charheight,fg,bg = struct.unpack('<HHHHBBBB', datablock.data)
		# x, y are the top left corner of the grid
		# gridwidth, gridheight are the size of the text grid in pixels and should be a multiple of charwidth. charheight
		# charwidth, charheight are the size of each character cell in the grid
		return PlaintextExtensionBlock((x, y), (gridwidth, gridheight), (charwidth, charheight), fg, bg, blocks)

	@staticmethod
	def write(f, block):
		(x,y),(gridwidth,gridheight),(charwidth,charheight),fg,bg,blocks = block
		blocks.insert(0, DataBlock(struct.pack('<HHHHBBBB', x, y, gridwidth, gridheight, charwidth, charheight, fg, bg)))
		DataBlocks.write(f, DataBlocks(blocks))

class RawExtensionBlock(collections.namedtuple('RawExtensionBlock', ['ident', 'blocks'])):
	@staticmethod
	def write(f, block):
		ident,blocks = block
		f.write(bytes([ident]))
		DataBlocks.write(f, blocks)

def readgifblock(f):
	match f.read(1)[0]:
		case 0x21:
			return readextensionblock(f)
		case 0x2C:
			return ImageBlock.read(f)
		case 0x3B:
			return EndBlock()
		case b:
			raise RuntimeError(f'unrecognized GIF block leading byte: 0x{b:0>2x}')

def writegifblock(f, block):
	match block:
		case CommentExtensionBlock() | ApplicationExtensionBlock() | GraphicControlExtensionBlock() | PlaintextExtensionBlock() | RawExtensionBlock():
			f.write(bytes([0x21]))
			writeextensionblock(f, block)
		case ImageBlock():
			f.write(bytes([0x2C]))
			ImageBlock.write(f, block)
		case EndBlock():
			f.write(bytes([0x3B]))
		case b:
			raise RuntimeError(f'unrecognized GIF block type: {type(block)}')

class DataBlocks(collections.namedtuple('DataBlocks', ['blocks'])):
	@staticmethod
	def read(f):
		blocks = []
		while True:
			block = DataBlock.read(f)
			if block.size == 0:
				return DataBlocks(blocks)
			blocks.append(block)

	@staticmethod
	def write(f, blocks):
		for block in blocks.blocks:
			DataBlock.write(f, block)
		DataBlock.write(f, DataBlock(b''))

	@property
	def data(self):
		return b''.join(block.data for block in self.blocks)

def readextensionblock(f):
	match f.read(1)[0]:
		case 0xFE:
			return CommentExtensionBlock.read(f)
		case 0xFF:
			return ApplicationExtensionBlock.read(f)
		case 0xF9:
			return GraphicControlExtensionBlock.read(f)
		case 0x01:
			return PlaintextExtensionBlock.read(f)
		case b:
			raise RuntimeError(f'unrecognized GIF block leading byte: 0x{b:0>2x}')

def writeextensionblock(f, block):
	match block:
		case CommentExtensionBlock():
			f.write(bytes([0xFE]))
			CommentExtensionBlock.write(f, block)
		case ApplicationExtensionBlock():
			f.write(bytes([0xFF]))
			ApplicationExtensionBlock.write(f, block)
		case GraphicControlExtensionBlock():
			f.write(bytes([0xF9]))
			GraphicControlExtensionBlock.write(f, block)
		case PlaintextExtensionBlock():
			f.write(bytes([0x01]))
			PlaintextExtensionBlock.write(f, block)
		case RawExtensionBlock():
			RawExtensionBlock.write(f, block)
		case b:
			raise RuntimeError(f'unrecognized GIF block type: {type(block)}')

def readgifblocks(f):
	blocks = []
	while True:
		block = readgifblock(f)
		if block == EndBlock():
			return blocks
		blocks.append(block)

def writegifblocks(f, blocks):
	for block in blocks:
		writegifblock(f, block)
	writegifblock(f, EndBlock())

class GIF(collections.namedtuple('GIF', ['header', 'blocks'])):
	@staticmethod
	def read(f):
		header = GIFHeader.read(f)
		blocks = readgifblocks(f)
		return GIF(header, blocks)

	@staticmethod
	def write(f, gif):
		header,blocks = gif
		GIFHeader.write(f, header)
		writegifblocks(f, blocks)