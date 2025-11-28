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
  
  def __str__(self) -> str:
    if self.typ[0].isalpha():
      return self.typ
    else:
      return f'\'{self.typ}\''

@dataclasses.dataclass(frozen = True)
class NonTerminal(Symbol):
  name: str
  
  def __str__(self) -> str:
    return f'@{self.name}'

# i'm not making a complex tokenizer today

@dataclasses.dataclass # type: ignore[misc] # ???
class Token:
  typ: str
  value: typing.Any

def maketoken(x: str) -> Token:
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

for target,productions in rules.items():
  print(target, ':=', ' | '.join(' '.join(str(t) for t in p) for p in productions))

# let's start with recursive descent
# built like parserlang
# every parser is an iterator
# requires right recursive rules for some reason

T = typing.TypeVar('T')

Parser = typing.Callable[[list[Token]], typing.Iterator[tuple[list[Token], T]]]

def concat(ps: typing.Iterable[Parser[typing.Any]]) -> Parser[list[typing.Any]]:
  # i don't know how to type hint this without Any, so here's a bunch of # type: ignore[misc]
  it = iter(ps) # type: ignore[misc]
  try:
    p = next(it) # type: ignore[misc]
    pc = concat(it) # type: ignore[misc]
    def parseconcat(s: list[Token]) -> typing.Iterator[tuple[list[Token], list[typing.Any]]]:
      for s1,v1 in p(s): # type: ignore[misc]
        for s2,v2 in pc(s1): # type: ignore[misc]
          yield s2, [v1, *v2] # type: ignore[misc]
    return parseconcat # type: ignore[misc]
  except StopIteration:
    return lambda s: iter([(s, [])])

def alternate(ps: typing.Iterator[Parser[T]]) -> Parser[T]:
  def parsealternate(s: list[Token]) -> typing.Iterator[tuple[list[Token], T]]:
    for p in ps:
      for sv in p(s):
        yield sv
  return parsealternate

def a1(l: typing.Iterable[T]) -> T:
  it = iter(l)
  v = next(it)
  try:
    next(it)
    assert False
  except StopIteration:
    return v

stack = []

@functools.cache # type: ignore[misc] # ???
def ruleparser(symbol: Symbol) -> Parser[Token]:
  if isinstance(symbol, Terminal):
    def parserule(s: list[Token]) -> typing.Iterator[tuple[list[Token], Token]]:
      #print(symbol)
      if len(s) == 0:
        return
      if s[0].typ == symbol.typ:
        yield s[1:], s[0]
    return parserule
  elif isinstance(symbol, NonTerminal):
    def parserule(s: list[Token]) -> typing.Iterator[tuple[list[Token], Token]]:
      #print(symbol)
      stack.append(symbol)
      #print(*[s.name for s in stack])
      for s1,v1 in alternate(concat(ruleparser(sym) for sym in production) for production in rules[symbol])(s): # type: ignore[misc] # who cares that this has Any in it tbh
        yield s1, Token(symbol.name, v1) # type: ignore[misc]
      stack.pop()
    return parserule
  else:
    assert False

def full(p: Parser[T]) -> Parser[T]:
  def parsefull(s: list[Token]) -> typing.Iterator[tuple[list[Token], T]]:
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
  production: tuple[Symbol, ...]
  position: int
  
  def advance(self) -> 'RuleState':
    # return a new RuleState with the parser position moved forward by one symbol
    return RuleState(self.target, self.production, self.position + 1)
  
  def next(self) -> typing.Optional[Symbol]:
    # return the next symbol after the parser position
    if self.position == len(self.production):
      return None
    return self.production[self.position]

def closure(state: set[RuleState], rules: dict[NonTerminal, list[list[Symbol]]]) -> set[RuleState]:
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

ParserState = frozenset[RuleState]

def generatestates(rules: dict[NonTerminal, list[list[Symbol]]], top: NonTerminal) -> tuple[ParserState, dict[ParserState, dict[Symbol, ParserState]]]:
  initialstate = frozenset(closure({RuleState(NonTerminal('__TOP__'), (top,), 0)}, rules))

  states: dict[ParserState, dict[Symbol, ParserState]] = {initialstate: {}}

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
      nextstatef = frozenset(closure(nextstate, rules))
      states[currstate][nextsymbol] = nextstatef
      states[nextstatef] = {}
      stack.append(nextstatef)
  
  return initialstate, states

initialstate,states = generatestates(rules, NonTerminal('Assign'))

mapping = {state:i for i,state in enumerate(states)}

for state in states:
  print(f'state {mapping[state]}')
  for rule in state:
    print(' ', rule.target, ':=', ' '.join(str(t) for t in rule.production[:rule.position] + ('.',) + rule.production[rule.position:]))
  if len(states[state]) > 0:
    print('transitions:')
    for nextsymbol in states[state]:
      print(f'  {nextsymbol}: {mapping[states[state][nextsymbol]]}')
  print()

print(tokens)

class Action:
  pass

class Shift(Action):
  nextstate: ParserState

class Reduce(Action):
  nextstate: ParserState
  to: NonTerminal
  count: int

class Accept(Action):
  pass

class Error(Action):
  pass

def parsesr(tokens: list[Token], states: dict[ParserState, dict[Symbol, ParserState]], initialstate: ParserState) -> None:
  stack: list[ParserState] = []
  state = initialstate
  tokenstack: list[Token] = []

  def pushstate(newstate: ParserState) -> None:
    nonlocal state
    stack.append(state)
    state = newstate

  def popstate() -> None:
    nonlocal state
    state = stack.pop()

  while True:
    if len(tokens) > 0:
      nexttoken = tokens[0]
    else:
      nexttoken = Token('__EOF__', None)
    if any(r.position == len(r.production) and r.target == NonTerminal('__TOP__') for r in state) and nexttoken.typ == '__EOF__':
      # accept
      return a1(tokenstack)
    elif Terminal(nexttoken.typ) in states[state]:
      # shift
      pushstate(states[state][Terminal(nexttoken.typ)])
      tokenstack.append(tokens[0])
      tokens = tokens[1:]
    elif any(r.position == len(r.production) for r in state):
      # reduce
      r = a1(r for r in state if r.position == len(r.production))
      for i in range(len(r.production)):
        popstate()
      reducedtokens = tokenstack[-len(r.production):]
      tokenstack = tokenstack[:-len(r.production)]
      pushstate(states[state][r.target])
      tokenstack.append(Token(r.target.name, reducedtokens))
    else:
      # error
      assert False

def tokentreestr(token: Token):
  if type(token.value) == list:
    return token.typ + ''.join('\n  ' + line for t in token.value for line in tokentreestr(t).split('\n'))
  else:
    return token.typ + ' ' + repr(token.value)

print(tokentreestr(parsesr(tokens, states, initialstate)))