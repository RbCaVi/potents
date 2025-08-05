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