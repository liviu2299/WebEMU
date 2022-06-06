class Time_Machine:

    def __init__(self,id,context,MEMORY,STACK,start_addr,step_index,stop_now,end_addr,LOG,ERROR):
        self.id = id
        self.context = context
        self.MEMORY = MEMORY
        self.STACK = STACK
        self.start_addr = start_addr
        self.step_index = step_index
        self.stop_now = stop_now
        self.end_addr = end_addr
        self.LOG = LOG
        self.ERROR = ERROR