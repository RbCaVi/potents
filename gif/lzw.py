import collections

# convert an iterable of bytes to an iterator of LZW codes
def unpacklzw(initialcodesize, data):
	bits = 0 # bitstring buffer
	bitcount = 0 # number of bits in the buffer

	codesize = initialcodesize # increments when the dictionary fills up

	RESET = 1 << (initialcodesize - 1) # code that resets the dictionary
	END = RESET + 1 # code to mark the end of the LZW data stream

	dictsize = END + 1 # number of entries in the dictionary

	data = iter(data)
	while True:
		while bitcount < codesize:
			bits |= next(data) << bitcount
			bitcount += 8
		code = bits & ((1 << codesize) - 1)
		bits >>= codesize
		bitcount -= codesize

		dictsize += 1

		if dictsize > 1 << codesize and codesize < 12: # it is the maximum value
			codesize += 1

		yield code

		if code == RESET:
			codesize = initialcodesize
			dictsize = END + 1
		if code == END: # CONCEAL: extra symbols can be added after the END code
			break

# convert an iterable of LZW codes to a string of bytes
def packlzw(initialcodesize, codes):
	return bytes(_packlzw(initialcodesize, codes)) # CONCEAL: extra bytes can be added after the compressed data

# convert an iterable of LZW codes to an iterator of bytes
def _packlzw(initialcodesize, codes):
	bits = 0 # bitstring buffer
	bitcount = 0 # number of bits in the buffer

	codesize = initialcodesize # increments when the dictionary fills up

	RESET = 1 << (initialcodesize - 1) # code that resets the dictionary
	END = RESET + 1 # code to mark the end of the LZW data stream

	dictsize = END + 1 # number of entries in the dictionary

	for code in codes:
		bits |= code << bitcount
		bitcount += codesize
		while bitcount >= 8:
			yield bits & 0xff
			bits >>= 8
			bitcount -= 8

		dictsize += 1 # a new symbol has been added to the dictionary

		if dictsize > 1 << codesize and codesize < 12:
			codesize += 1

		if code == RESET:
			codesize = initialcodesize
			dictsize = END + 1
		if code == END:
			if bitcount > 0:
				yield bits # CONCEAL: extra bits can be added after the END code
			return # CONCEAL: extra symbols can be added after the END code

fileout1 = open('output1.txt', 'w')

# decompress an iterable of LZW codes into an iterator of data items (used as indexes into the color table)
def decompresslzw(initialcodesize, codes, report = lambda index, length: None):
	RESET = 1 << (initialcodesize - 1) # code that resets the dictionary
	END = RESET + 1 # code to mark the end of the LZW data stream

	codeoptions = collections.deque() # list of (code, chars since decoded (inclusive), dictionary, dictionary size when decoded)

	dictionary = [[None] for i in range(1 << (initialcodesize - 1))] + [[], [None]]

	lastcode = RESET

	for code in codes:
		if code == END:
			for code2,chars,dictionary2,length in codeoptions: # drain
				prefixes = [code for code,word in enumerate(dictionary2) if code < length and word == chars[:len(word)]]
				index = prefixes.index(code2)
				length = len(prefixes)
				print(code, prefixes, index, length, file = fileout1)
				report(index, length)
			return # CONCEAL: extra codes can be added after the END code
		if lastcode != RESET:
			dictionary.append(dictionary[lastcode] + [dictionary[lastcode if code == len(dictionary) or code == RESET else code][0]])
		codeoptions.append((code, [], dictionary, len(dictionary)))
		if code == RESET:
			# the spec requires the first code to be RESET, so I can initialize the dictionary here instead of before the loop
			dictionary = [[i] for i in range(1 << (initialcodesize - 1))] + [[], [None]] # initial dictionary plus two extra codes
		for code2,chars,dictionary2,length in codeoptions:
			chars += dictionary[code]
		while len(codeoptions) > 0:
			code2,chars,dictionary2,length = codeoptions[0]
			if chars in dictionary2[:length]:
				break
			codeoptions.popleft()
			prefixes = [code for code,word in enumerate(dictionary2) if code < length and word == chars[:len(word)]]
			index = prefixes.index(code2)
			length = len(prefixes)
			print(code, prefixes, index, length, file = fileout1)
			report(index, length)
		yield from dictionary[code]
		lastcode = code

# decompress an iterable of LZW codes into an iterator of data items (used as indexes into the color table)
def decompresslzwquick(initialcodesize, codes):
	RESET = 1 << (initialcodesize - 1) # code that resets the dictionary
	END = RESET + 1 # code to mark the end of the LZW data stream

	codeoptions = [] # list of (code, chars since decoded (inclusive), dictionary, dictionary size when decoded)

	dictionary = [[None] for i in range(1 << (initialcodesize - 1))] + [[], [None]]

	lastcode = RESET

	for code in codes:
		if code == END:
			return # CONCEAL: extra codes can be added after the END code
		if lastcode != RESET:
			if code != RESET:
				dictionary.append(dictionary[lastcode] + [dictionary[lastcode if code == len(dictionary) else code][0]])
		if code == RESET:
			# the spec requires the first code to be RESET, so I can initialize the dictionary here instead of before the loop
			dictionary = [[i] for i in range(1 << (initialcodesize - 1))] + [[], [None]] # initial dictionary plus two extra codes
		for code2,chars,dictionary2,length in codeoptions:
			chars += dictionary[code]
		yield from dictionary[code]
		lastcode = code

fileout3 = open('output3.txt', 'w')

# compress an iterable of data items into an iterator of LZW codes
def compresslzw(initialcodesize, data, choose = lambda length: length - 1):
	def resetdict():
		dictionary = collections.defaultdict(list, {(i,):[i] for i in range(1 << (initialcodesize - 1))})
		dictionary[()] = [RESET]
		dictsize = END + 1 # number of entries in the dictionary
		return dictionary, dictsize

	RESET = 1 << (initialcodesize - 1) # code that resets the dictionary
	END = RESET + 1 # code to mark the end of the LZW data stream

	dictionary,dictsize = resetdict()

	assert choose(1) == 0
	yield RESET # the spec requires the first code to be RESET

	word = []
	for x in data:
		if tuple(word) not in dictionary:
			# list of all LZW codes that can be emitted at this point - prefixes of word that are in the dictionary
			choices = [(i, code, word[:i]) for i in range(0, len(word) + 1) for code in dictionary[tuple(word[:i])]]
			choices.sort(key = lambda x: x[1])
			choice = choose(len(choices))
			i,code,_ = choices[choice] # CONCEAL: the choice of code can hold information
			print(code, [choice[1] for choice in choices], choice, len(choices), file = fileout3)
			yield code
			if code == RESET:
				dictionary,dictsize = resetdict()
			elif dictsize < 4096:
				dictionary[tuple(word[:i + 1])].append(dictsize)
				dictsize += 1
			word = word[i:]
		word.append(x)

	# drain the last part
	while len(word) > 0:
		# list of all LZW codes that can be emitted at this point - prefixes of word that are in the dictionary
		choices = [(i, code, word[:i]) for i in range(0, len(word) + 1) for code in dictionary[tuple(word[:i])]]
		choices.sort(key = lambda x: x[1])
		choice = choose(len(choices))
		i,code,_ = choices[choice] # CONCEAL: the choice of code can hold information
		print(code, [choice[1] for choice in choices], choice, len(choices), file = fileout3)
		yield code
		if code == RESET:
			dictionary,dictsize = resetdict()
		elif dictsize < 4096:
			dictionary[tuple(word[:i + 1])].append(dictsize)
			dictsize += 1
		word = word[i:]

	yield END # CONCEAL: extra symbols can be added after the END code