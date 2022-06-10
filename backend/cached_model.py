class Time_Machine:

    def __init__(self,id,context,MEMORY,STACK,start_addr,stop_now,end_addr,LOG,ERROR,editor_mapping,error_line):
        self.id = id
        self.context = context
        self.MEMORY = MEMORY
        self.STACK = STACK
        self.start_addr = start_addr
        self.stop_now = stop_now
        self.end_addr = end_addr
        self.LOG = LOG
        self.ERROR = ERROR
        self.editor_mapping = editor_mapping
        self.error_line = error_line