import re

def findWholeWord(w):
  return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

def line_addr_mapping(code,disassembled):
  """
  Returns a dictionary mapping editor lines by memory address
  """
  j = 0
  dict = {}
  for i in range(len(code)):
    if findWholeWord(disassembled[j]["instr"])(code[i]):
      dict[disassembled[j]["addr"]] = i
      j = j+1
  
  return dict
