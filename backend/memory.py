import json

class Memory:   
    def __init__(self, addr: str, value: int):
        self.addr = addr
        self.value = value

    def __str__(self):
        return "addr: {} value: {}".format(self.addr, self.value)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__)