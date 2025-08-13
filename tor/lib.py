import base64

class Peekable:
  def __init__(self, it):
    self.it = iter(it)
    self.buffer = []
  
  def __iter__(self):
    return self
  
  def __next__(self):
    if len(self.buffer) == 1:
      return self.buffer.pop()
    else:
      return next(self.it)
  
  def peek(self):
    if len(self.buffer) == 0:
      self.buffer.append(next(self.it))
    return self.buffer[0]

# convert a function that returns a generator to one that returns a list
def generator_to_list(f):
  return lambda *args, **kwargs: [*f(*args, **kwargs)]

# convert a list of 'key=value' strings to a dictionary
def params_to_dict(params):
  if params is None:
    return None
  split = [kv.split('=') for kv in params]
  out = {k:v for k,v in split}
  assert len(out) == len(split), 'duplicate key :('
  return out

# handles None and missing padding
def b64decode(data):
  if data is None:
    return None
  return base64.b64decode(data + '==')

# optional monad or something idk
def optional(f):
  def f2(x):
    if x is None:
      return None
    return f(x)
  return f2

# sugar
def optional_chain(*fs):
  def f(x):
    if x is None:
      return None
    for f in fs:
      x = f(x)
    return x
  return f

# verify the length of a list
def assert_one(l):
  l = [*l]
  assert len(l) == 1
  return l[0]

def assert_optional(l, default = None):
  l = [*l]
  assert len(l) <= 1
  if len(l) == 0:
    return default
  return l[0]

def assert_nonempty(l):
  l = [*l]
  assert len(l) > 0
  return l

# like get_line_*
# but takes a line instead of taking it from an iterator
def unwrap_line_args_no_object(line):
  assert line.object_name is None
  return line.arguments

def unwrap_line_args_with_object(object_name, line):
  assert line.object_name == object_name
  return line.arguments, line.object_data

def unwrap_line_args_with_object_c(object_name): # curried
  def unwrap_line_args_with_object_b(line): # bound
    return unwrap_line_args_with_object(object_name, line)
  return unwrap_line_args_with_object_b

# boolean :)
def tobool(x):
  assert x in ['0', '1']
  return x == '1'

# get `size` bytes starting from `offset`
def bytes_from(size, data, offset): # argument order to match struct.unpack_from()
  assert offset + size <= len(data), 'not enough bytes to return from bytes_from()'
  return data[offset:offset + size]