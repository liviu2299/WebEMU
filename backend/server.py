from multiprocessing import context
from flask import Flask, request, session
from flask_session import Session
from emulator import Emulator
from cached_model import Time_Machine
import jsonpickle

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.secret_key = "devserver"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # TODO: Bug fix when first line is empty

    @app.route("/", methods=['POST'])
    def home():
        id = request.json['id']
        
        session[id] = Time_Machine(
            id,
            0,
            {
            "size": 0x100400-0x100000,
            "starting_address": 0x100000,
            },
            {
            "size": 0x100400-0x100350,
            "starting_address": 0x100350,
            },
            0x100000,
            0,
            False,
            0,
            [],
            None).__dict__

        return{
            "message": ('You logged with id: %s' %id) 
        }

    @app.route("/compute", methods=['POST'])
    def compute():
        id = request.json['id']
        data = request.json['data']
        code = data.splitlines()
        emu = Emulator()
        
        # GET CACHE ( TODO: cleanup with functions )
        old_context = session[id]
        emu.MEMORY["starting_address"] = old_context["MEMORY"]["starting_address"]
        emu.MEMORY["size"] = old_context["MEMORY"]["size"]
        emu.STACK["starting_address"] = old_context["STACK"]["starting_address"]
        emu.STACK["size"] = old_context["STACK"]["size"]
        emu.uc = emu.initiate_uc()

        # RUN
        emu.run(code)
        emu.update_data()

        try:
            if emu.ERROR == "None":
                return{
                    "registers": emu.REGISTERS,
                    "memory": emu.MEMORY["data"],
                    "stack": emu.STACK["data"],
                    "error": emu.ERROR,
                    'log': emu.LOG,
                    'state': int(emu.state)
                }   
            else: 
                return{
                "error": emu.ERROR,
                'log': emu.LOG,
                'state': int(emu.state)
            }
        finally:
            emu.stop()

    @app.route("/compile", methods=['POST'])
    def compile():
        id = request.json['id']
        data = request.json['data']
        code = data.splitlines()
        emu = Emulator()

        # GET CACHE ( TODO: cleanup with functions )
        old_context = session[id]
        emu.MEMORY["starting_address"] = old_context["MEMORY"]["starting_address"]
        emu.MEMORY["size"] = old_context["MEMORY"]["size"]
        emu.STACK["starting_address"] = old_context["STACK"]["starting_address"]
        emu.STACK["size"] = old_context["STACK"]["size"]
        emu.uc = emu.initiate_uc()

        # RUN
        emu.compile(code)
        emu.update_data()

        # UPDATE CACHE ( Saving memory and memory indexes )
        mem = emu.uc.mem_read(emu.MEMORY["starting_address"], emu.MEMORY["size"])
        encrypted_mem = bytes(mem)

        session[id] = Time_Machine(
            id,
            0,
            {
            "size": emu.MEMORY["size"],
            "encrypted_mem": encrypted_mem,
            "starting_address": emu.MEMORY["starting_address"],
            },
            emu.STACK,
            emu.MEMORY["starting_address"],
            session[id]["step_index"],
            session[id]["stop_now"],
            emu.end_addr,
            emu.LOG,
            session[id]["ERROR"]
        ).__dict__

        try:
            if emu.ERROR == "None":
                return{
                    "registers": emu.REGISTERS,
                    "memory": emu.MEMORY["data"],
                    "stack": emu.STACK["data"],
                    "error": emu.ERROR,
                    'log': emu.LOG,
                    'state': int(emu.state)
                }   
            else: 
                return{
                "error": emu.ERROR,
                'log': emu.LOG,
                'state': int(emu.state)
            }
        finally:
            emu.stop()

    @app.route("/step", methods=['POST'])
    def step():
        id = request.json['id']
        data = request.json['data']
        code = data.splitlines()
        emu = Emulator()

        # GET CACHE ( TODO: cleanup with functions )
        old_context = session[id]

            # 1) Updates emulator
        if old_context["context"] is not 0:
            uc_context = jsonpickle.decode(old_context["context"])
            emu.uc.context_restore(uc_context)
        
        emu.MEMORY["starting_address"] = old_context["MEMORY"]["starting_address"]
        emu.MEMORY["size"] = old_context["MEMORY"]["size"]
        emu.STACK["starting_address"] = old_context["STACK"]["starting_address"]
        emu.STACK["size"] = old_context["STACK"]["size"]
        emu.start_addr = old_context["start_addr"]
        emu.step_index = old_context["step_index"]
        emu.stop_now = old_context["stop_now"]
        emu.end_addr = old_context["end_addr"]
        emu.LOG = old_context["LOG"]
        
        if old_context["context"] is 0:
            emu.uc = emu.initiate_uc()

            # 2) Updates memory
        encrypted_mem = session[id]["MEMORY"]["encrypted_mem"]
        emu.uc.mem_write(emu.MEMORY["starting_address"], bytes(encrypted_mem))
        emu.update_data()

        # STEP
        emu.step()
        emu.update_data()
        
        # UPDATE CACHE
        unicorn_context = emu.uc.context_save()
        session[id] = Time_Machine(
            id,
            jsonpickle.encode(unicorn_context),
            {
            "size": emu.MEMORY["size"],
            "encrypted_mem": encrypted_mem,
            "starting_address": emu.MEMORY["starting_address"],
            },
            emu.STACK,
            emu.start_addr,
            emu.step_index,
            emu.stop_now,
            emu.end_addr,
            emu.LOG,
            emu.ERROR
        ).__dict__

        if emu.ERROR == "None":
            return{
                "registers": emu.REGISTERS,
                "memory": emu.MEMORY["data"],
                "stack": emu.STACK["data"],
                "error": emu.ERROR,
                'log': emu.LOG,
                'state': int(emu.state)
            }   
        else: 
            return{
            "error": emu.ERROR,
            'log': emu.LOG,
            'state': int(emu.state)
        }
   
    @app.route("/update", methods=['POST'])
    def update():
        id = request.json['id']
        data = request.json['data']

        emu = Emulator()
        emu.update_uc_parameters(data)

        # UPDATE CACHE       
        session[id] = Time_Machine(
            id,
            session[id]["context"],
            {
            "size": data['options']['MEMORY']['size'],
            "starting_address": 0x100000,   
            },
            {
            "size": data['options']['STACK']['size'],
            "starting_address": data['options']['STACK']['starting_address'],     
            },
            session[id]["start_addr"],
            session[id]["step_index"],
            session[id]["stop_now"],
            session[id]["end_addr"],
            session[id]["LOG"],
            session[id]["ERROR"]
        ).__dict__

        return{
            'message': "Done"
        }

    return app

