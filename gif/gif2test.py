import gif2

import io

with open('cupcake.gif', 'rb') as f:
	gif = gif2.GIF.read(f)
	f.seek(0)
	data1 = f.read()

with io.BytesIO() as f:
	gif2.GIF.write(f, gif)
	f.seek(0)
	data2 = f.read()

print(len(data1), len(data2))

for i in range(0, len(data1), 64):
	chunk1 = data1[i:i + 64]
	chunk2 = data2[i:i + 64]
	if chunk1 != chunk2:
		print(chunk1 == chunk2)