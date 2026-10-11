# steganographic gif recoder
i made a couple of programs that can hide some amount of data inside a gif file

`gif2.py` and `lzw.py` are the core of this - `gif2.py` is a gif file decoder /
encoder that returns basically the raw gif file structure, and `lzw.py` has
functions to encode and decode the LZW compression used in gif files.

`{conceal,reveal}*.py` are pairs of programs; `conceal*.py` takes a gif
(hardcoded as `cupcake.gif` right now) and creates a copy that is (hopefully
exactly) the same visually, but containing some hidden data that `reveal*.py`
is able to extract.

`gif2test.py` tests if `gif2.py` and `lzw.py` can perfectly recreate a gif file

the rest of the programs (`gif.py`, `2hrgif.py`, `writegif.py`, and
`gifwritetest.py`) are an older iteration of this project