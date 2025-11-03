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
freq = Value(440, dtype = float)
factor = Value(0.95, dtype = float)

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

class UserSine(G):
  def __init__(self):
    super().__init__()
    self.position = 0
  
  def _advance(self, frames):
    factor = 2 * 3.14159 / 44100
    w = freq.value * factor
    out = np.sin(np.arange(frames, dtype = np.float64) * w + self.position)
    self.position += frames * w
    return np.stack([out, out], axis = 1)

class Delay(G):
  def __init__(self, delay, last):
    super().__init__(inputs = (last,))
    self.delay = delay
    self.delaybuffer = numpy.zeros((delay, 2))
  
  def _advance(self, frames):
    b = np.concat((self.delaybuffer, self.inputs[0].buffer), axis = 0)
    self.delaybuffer = b[-self.delay:]
    return b[:-self.delay]

class Input(G):
  def _advance(self, frames):
    pass

class Lowpass(G):
  def __init__(self, factor, last):
    super().__init__(inputs = (last,))
    self.factor = factor
    self.last = last
    self.value = np.zeros((1, 2))
  
  def _advance(self, frames):
    self.factor = factor.value
    out = np.zeros_like(self.last.buffer)
    for i in range(self.last.buffer.shape[0]):
      self.value = self.factor * self.value + (1 - self.factor) * self.last.buffer[i]
      out[i] = self.value
    return out

x = UserSine()
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

def volume_slider_callback(value):
  volume.value = float(value)

def freq_slider_callback(value):
  freq.value = float(value)

def main_tkinter():
  root = tk.Tk()
  frm = ttk.Frame(root, padding = 10)
  frm.grid()
  ttk.Label(frm, text = "volume").grid(column = 0, row = 0)
  ttk.Button(frm, text = "DIE", command = s.exit).grid(column = 0, row = 1)
  ttk.Scale(frm, from_ = 0, to = 1, value = volume.value, command = volume.setvalue).grid(column = 1, row = 0)
  ttk.Scale(frm, from_ = 100, to = 1000, value = freq.value, command = freq.setvalue).grid(column = 1, row = 1)
  ttk.Scale(frm, from_ = 0, to = 1, value = factor.value ** 20, command = lambda v: factor.setvalue(float(v) ** (1 / 20))).grid(column = 1, row = 2)
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