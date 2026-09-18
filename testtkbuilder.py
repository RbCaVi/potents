from tkbuilder import Grid, LabelBuilder, FrameBuilder, ButtonBuilder
from tkinter import Tk, Label

ghost = FrameBuilder(geometry = Grid(column = 1, row = 1), children = [
	LabelBuilder(text = 'line 1', geometry = Grid(column = 0, row = 0)),
	LabelBuilder(text = 'line 2', geometry = Grid(column = 0, row = 1), key = 'text'),
	ButtonBuilder(text = 'but', command = lambda: text.configure(text = 'no'), geometry = Grid(column = 0, row = 2)),
])

root = Tk()

Label(root, text = 'hi <3').grid(column = 0, row = 0)
Label(root, text = 'hi 2 <3').grid(column = 1, row = 0)
Label(root, text = 'hi 3 <3').grid(column = 0, row = 1)

parts = ghost.build(root, {})
#print(parts)
text = parts['text']

root.mainloop()