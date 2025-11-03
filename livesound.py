import sounddevice as sd
import numpy as np
import numpy.random
import tkinter as tk
import tkinter.ttk as ttk
import threading as th
import time as t
import sys as s
import abc as abc

class Value:
  def __init__(self, value, dtype = lambda x: x):
    self.dtype = dtype
    self.setvalue(value)
  
  def setvalue(self, value):
    self.value = self.dtype(value)

volume = Value(0.5, dtype = float)

class G(abc.ABC):
  def __init__(self, inputs = ()):
    self.inputs = inputs
    self.setframe(0)
  
  def setframe(self, frame):
    self.frame = frame
    self.buffer = numpy.zeros((0, 2))
  
  def advance(self, frames):
    self.frame += frames
    self.buffer = self._advance(frames)
    return self.buffer
  
  @abc.abstractmethod
  def _advance(self, frames):
    # returns the next `frames` audio frames
    pass
  
  @abc.abstractmethod
  def createwidget(self, root):
    # creates tkinter widgets under `root` that control this [thing]
    # `root` is a frame or equivalent widget
    pass

class Sine(G):
  def __init__(self):
    super().__init__()
    self.position = 0
    self.freq = 440
  
  def _advance(self, frames):
    factor = 2 * 3.14159 / 44100
    w = self.freq * factor
    out = np.sin(np.arange(frames, dtype = np.float64) * w + self.position)
    self.position += frames * w
    return np.stack([out, out], axis = 1)
  
  def setfreq(self, freq):
    self.freq = float(freq)
  
  def createwidget(self, root):
    ttk.Label(root, text = "sine").grid(column = 0, row = 0)
    ttk.Scale(root, from_ = 100, to = 1000, value = self.freq, command = self.setfreq).grid(column = 0, row = 1)

class Delay(G):
  def __init__(self, delay, last):
    super().__init__(inputs = (last,))
    self.delay = delay
    self.delaybuffer = numpy.zeros((delay, 2))
  
  def _advance(self, frames):
    b = np.concat((self.delaybuffer, self.inputs[0].buffer), axis = 0)
    self.delaybuffer = b[-self.delay:]
    return b[:-self.delay]
  
  def createwidget(self, root):
    ttk.Label(root, text = "hi").grid(column = 0, row = 0)

class Input(G):
  def _advance(self, frames):
    pass
  
  def createwidget(self, root):
    ttk.Label(root, text = "input").grid(column = 0, row = 0)

class Lowpass(G):
  def __init__(self, factor, last):
    super().__init__(inputs = (last,))
    self.factor = factor
    self.last = last
    self.value = np.zeros((1, 2))
  
  def _advance(self, frames):
    out = np.zeros_like(self.last.buffer)
    for i in range(self.last.buffer.shape[0]):
      self.value = self.factor * self.value + (1 - self.factor) * self.last.buffer[i]
      out[i] = self.value
    return out
  
  def setfactor(self, factor):
    self.factor = float(factor) ** (1 / 20)
  
  def createwidget(self, root):
    ttk.Label(root, text = "lowpass").grid(column = 0, row = 0)
    ttk.Scale(root, from_ = 0, to = 1, value = self.factor ** 20, command = self.setfactor).grid(column = 0, row = 1)

x = Sine()
a = Input()
b = Lowpass(0.95, a)

def audio_callback(indata, outdata, frames, time, status):
  if status:
    print('STATUS:', status)
  a.buffer = indata
  b.advance(frames)
  outdata[:] = b.buffer * volume.value# + x.advance(frames) * (1 - volume.value)
  #outdata[:] = x.advance(frames) * volume.value

def main_audio():
  #sd.play([float(i) for i in range(100)] * 300, 44100)
  #sd.wait()
  #sd.play([float(i/5) for i in range(100)] * 300, 44100)
  #sd.wait()
  #sd.play([float(i/10) for i in range(100)] * 300, 44100)
  #sd.wait()
  #sd.play([float(i/20) for i in range(100)] * 300, 44100)
  #sd.wait()
  #sd.play([float(i/50) for i in range(100)] * 300, 44100)
  #sd.wait()
  #sd.play([float(i/100) for i in range(100)] * 300, 44100)
  #sd.wait()
  
  with sd.Stream(channels = 2, callback = audio_callback, device = (3, 5), samplerate = 44100):
    while True:
      sd.sleep(5000)

def main_tkinter():
  root = tk.Tk()
  frm = ttk.Frame(root, padding = 10)
  frm.grid()
  ttk.Label(frm, text = "volume").grid(column = 0, row = 0)
  ttk.Button(frm, text = "DIE", command = s.exit).grid(column = 0, row = 1)
  ttk.Scale(frm, from_ = 0, to = 1, value = volume.value, command = volume.setvalue).grid(column = 1, row = 0)
  (canvas := tk.Canvas(frm, width = 400, height = 300, bg = "white")).grid(column = 0, row = 3, columnspan = 2)
  def createwindow(canvas):
    wid = canvas.create_window(0, 0, anchor = tk.NW, window = (w := ttk.Frame(root, padding = (10, 10, 10, 10))))
    def down(event):
      global mx, my, grabbed
      mx = event.x_root
      my = event.y_root
      grabbed = wid
    def move(event):
      global mx, my
      canvas.move(grabbed, event.x_root - mx, event.y_root - my)
      mx = event.x_root
      my = event.y_root
    w.bind('<Button-1>', down)
    w.bind('<B1-Motion>', move)
    return w
  ttk.Button(createwindow(canvas), text = "DIE", command = s.exit).grid(column = 0, row = 1)
  x.createwidget(createwindow(canvas))
  a.createwidget(createwindow(canvas))
  b.createwidget(createwindow(canvas))
  root.mainloop()

def main():
  thread_audio = th.Thread(target = main_audio, daemon = True)
  thread_tkinter = th.Thread(target = main_tkinter, daemon = True)
  thread_audio.start()
  thread_tkinter.start()
  while thread_tkinter.is_alive() and thread_audio.is_alive():
    thread_tkinter.join(0.1)
  s.exit()

main()