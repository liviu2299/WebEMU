import re
from types import NoneType

def findWholeWord(w):
  return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

def line_addr_mapping(code,disassembled):
  """
  Returns a dictionary mapping editor lines by memory address
  """
  j = 0
  dict = {}
  for i in range(len(code)):
    if j < len(disassembled):
      if findWholeWord(disassembled[j]["instr"])(code[i]):
        dict[disassembled[j]["addr"]] = i
        j = j+1
  
  return dict

def parse_comments(code):
  for line in code[:]:
    if line.startswith("#"):
      code.remove(line)
  return code

def formatNoneType(code):
  new_code = code
  if not new_code:
    new_code.append('')
    new_code.append('')
    return new_code

  if new_code[0] == '' and len(new_code) == 1:
    new_code.append('')
    return new_code
    
  return new_code