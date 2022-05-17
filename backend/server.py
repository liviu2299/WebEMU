from flask import Flask, request
from emulator import Emulator

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    emu = Emulator()

    @app.route("/compute", methods=['POST'])
    def compute():
        data = request.json['data']
        code = data.splitlines()
        
        emu.run(code)
        emu.update_data()

        try:
            if emu.ERROR == "None":
                return{
                    "registers": emu.REGISTERS,
                    "memory": emu.MEMORY["data"],
                    "stack": emu.STACK["data"],
                    "error": emu.ERROR,
                    'log': emu.LOG
                }   
            else: 
                return{
                "error": emu.ERROR,
                'log': emu.LOG
            }
        finally:
            emu.stop()

    @app.route("/compile", methods=['POST'])
    def compile():
        data = request.json['data']
        code = data.splitlines()

        emu.compile(code)
        emu.get_memory()

        try:
            if emu.ERROR == "None":
                return{
                    "memory": emu.MEMORY["data"],
                    "stack": emu.STACK["data"],
                    "error": emu.ERROR,
                    'log': emu.LOG
                }   
            else: 
                return{
                "error": emu.ERROR,
                'log': emu.LOG
            }
        finally:
            emu.stop()

        
    emu = Emulator()

    @app.route("/step", methods=['POST'])
    def step():
        data = request.json['data']
        code = data.splitlines()
        
        emu.run(code)
        emu.update_data()

        try:
            if emu.ERROR == "None":
                return{
                    "registers": emu.REGISTERS,
                    "memory": emu.MEMORY["data"],
                    "stack": emu.STACK["data"],
                    "error": emu.ERROR,
                    'log': emu.LOG
                }   
            else: 
                return{
                "error": emu.ERROR,
                'log': emu.LOG
            }
        finally:
            emu.stop()

    return app

