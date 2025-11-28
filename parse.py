# parsing

# uhh
# shift reduce
# recursive descent
# "superposition" - added to others

# the idea of superposition is to have multiple interpretations of a sequence of characters or tokens
# and it parses the tokens into all possible parse trees
# parserlang is built on this idea, but it doesn't cache anything, so anything after an ambiguous part is parsed multiple times

import dataclasses
import typing
import functools

class Symbol:
  pass

@dataclasses.dataclass(frozen = True)
class Terminal(Symbol):
  typ: str
  
  def __str__(self):
    if self.typ[0].isalpha():
      return self.typ
    else:
      return f'\'{self.typ}\''

@dataclasses.dataclass(frozen = True)
class NonTerminal(Symbol):
  name: str
  
  def __str__(self):
    return f'@{self.name}'

# i'm not making a complex tokenizer today

@dataclasses.dataclass
class Token:
  typ: str
  value: typing.Any

def maketoken(x):
  if x.isdigit():
    return Token('int', int(x))
  if x.isalnum():
    return Token('id', x)
  return Token(x, x)

tokens = [*map(maketoken, 'a = 1 + 5 * 5'.split())]

print(tokens)

def production(production: list[str]) -> list[Symbol]:
  return [NonTerminal(s) if s[0].isupper() else Terminal(s) for s in production]

rules = {
  NonTerminal('Assign'): [production(['id', '=', 'Sum'])],
  NonTerminal('Sum'): [production(['Product']), production(['Product', '+', 'Sum'])],
  NonTerminal('Product'): [production(['Value']), production(['Value', '*', 'Product'])],
  NonTerminal('Value'): [production(['int']), production(['id'])],
}

for rule,productions in rules.items():
  print(rule, ':=', ' | '.join(' '.join(str(t) for t in p) for p in productions))

# let's start with recursive descent
# built like parserlang
# every parser is an iterator
# requires right recursive rules for some reason

def concat(ps):
  it = iter(ps)
  try:
    p = next(it)
    pc = concat(it)
    def parseconcat(s):
      for s1,v1 in p(s):
        for s2,v2 in pc(s1):
          yield s2, [v1, *v2]
    return parseconcat
  except StopIteration:
    return lambda s: iter([[s, []]])

def alternate(ps):
  def parsealternate(s):
    for p in ps:
      for sv in p(s):
        yield sv
  return parsealternate

def a1(l):
  it = iter(l)
  v = next(it)
  try:
    next(it)
    assert False
  except StopIteration:
    return v

stack = []

@functools.cache
def ruleparser(symbol):
  if isinstance(symbol, Terminal):
    def parserule(s):
      #print(symbol)
      if len(s) == 0:
        return
      if s[0].typ == symbol.typ:
        yield s[1:], s[0]
    return parserule
  elif isinstance(symbol, NonTerminal):
    def parserule(s):
      #print(symbol)
      stack.append(symbol)
      #print(*[s.name for s in stack])
      yield from alternate(concat(ruleparser(sym) for sym in production) for production in rules[symbol])(s)
      stack.pop()
    return parserule

def full(p):
  def parsefull(s):
    for s,v in p(s):
      if s == []:
        yield s,v
  return parsefull

for s,v in full(ruleparser(NonTerminal('Assign')))(tokens):
  print(s, v)

# shift reduce
# left recursive rules to minimize the size of the stack

rules = {
  NonTerminal('Assign'): [production(['id', '=', 'Sum'])],
  NonTerminal('Sum'): [production(['Product']), production(['Sum', '+', 'Product'])],
  NonTerminal('Product'): [production(['Value']), production(['Product', '*', 'Value'])],
  NonTerminal('Value'): [production(['int']), production(['id'])],
}

# i read this from the dragon book
# https://web.archive.org/web/20160305041504/http://dragonbook.stanford.edu/lecture-notes/Stanford-CS143/08-Bottom-Up-Parsing.pdf
# start with the top level rule: P -> . Assign with the parser position (.) at the beginning
# compute the closure of it - all rules that can match directly after it
# in this case, [P -> . Assign, Assign -> . id '=' Sum]
# that's the first "configurating set" or parser state
# each symbol after the parser position in any of the rules corresponds to a transition to another state of the parser
# the state it transitions to includes all states where that symbol was after the parser position, with the parser position advanced by one step
# and the closure of those rules
# this one would have transitions Assign:[P -> Assign .] and id:[Assign -> id . '=' Sum]
# then [Assign -> int . '=' Sum] has the transition '=':[Assign -> int '=' . Sum, Sum -> . Sum '+' Product, Sum -> . Product, Product -> . Product '*' Value, Product -> . Value, Value -> . int, Value -> . id]
# and so on

# i did this by hand on paper and got 11 parser states
# [P -> . Assign, Assign -> . id '=' Sum]
# [P -> Assign .]
# [Assign -> ud . '=' Sum]
# [Assign -> int '=' . Sum, Sum -> . Sum '+' Product, Sum -> . Product, Product -> . Product '*' Value, Product -> . Value, Value -> . int, Value -> . id]
# [Assign -> int '=' Sum ., Sum -> Sum . '+' Product]
# [Sum -> Sum '+' . Product, Product -> . Product '*' Value, Product -> . Value, Value -> . int, Value -> . id]
# [Sum -> Product ., Product -> Product . '*' Value]
# [Product -> Product '*' . Value, Value -> . int, Value -> . id]
# [Product -> Value .]
# [Value -> int .]
# [Value -> id .]

# i missed 2 T_T
# [Sum -> Sum '+' Product ., Product -> Product . '*' Value]
# [Product -> Product '*' Value .]

@dataclasses.dataclass(frozen = True)
class RuleState:
  target: NonTerminal
  production: list[Symbol]
  position: int
  
  def advance(self):
    # return a new RuleState with the parser position moved forward by one symbol
    return RuleState(self.target, self.production, self.position + 1)
  
  def next(self):
    # return the next symbol after the parser position
    if self.position == len(self.production):
      return None
    return self.production[self.position]

def closure(state):
  # computes and returns the closure of a set of rules
  out = set()
  stack = [*state]
  print('stack', stack)
  while len(stack) > 0:
    currrule = stack.pop()
    out.add(currrule)
    sym = currrule.next()
    if isinstance(sym, NonTerminal):
      for newrule in [RuleState(sym, tuple(production), 0) for production in rules[sym]]:
        if newrule not in out:
          stack.append(newrule)
  print(out)
  return out
  

initialstate = frozenset(closure({RuleState(NonTerminal('__TOP__'), (NonTerminal('Assign'),), 0)}))

states = {initialstate: set()}

stack = [initialstate]
while len(stack) > 0:
  currstate = stack.pop()
  for nextsymbol in {r.next() for r in currstate}:
    if nextsymbol is None:
      continue
    nextstate = set()
    for rule in currstate:
      if rule.next() == nextsymbol: # quadratic worst case <3 this is very important
        nextstate.add(rule.advance())
    nextstate = frozenset(closure(nextstate))
    states[currstate].add(nextstate)
    states[nextstate] = set()
    stack.append(nextstate)

print(states)

mapping = {state:i for i,state in enumerate(states)}

for state in states:
  print(f'state {mapping[state]}')
  for rule in state:
    print(rule.target, ':=', ' '.join(str(t) for t in rule.production[:rule.position] + ('.',) + rule.production[rule.position:]))

