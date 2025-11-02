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

class G(abc.ABC):
  def __init__(self):
    self.setframe(0)
  
  def setframe(self, frame):
    self.frame = frame
  
  @abc.abstractmethod
  def advance(self, frames):
    pass

class X(G):
  def __init__(self):
    super().__init__()
    self.position = 0
  
  def advance(self, frames):
    factor = 2 * 3.14159 / 44100
    w = freq.value * factor
    out = np.sin(np.arange(frames, dtype = np.float64) * w + self.position)
    self.frame += frames
    self.position += frames * w
    return np.stack([out, out], axis = 1)

x = X()

def audio_callback(indata, outdata, frames, time, status):
  if status:
    print('STATUS:', status)
  #outdata[:] = indata * volume.value + x.advance(frames) * (1 - volume.value)
  outdata[:] = x.advance(frames) * volume.value

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