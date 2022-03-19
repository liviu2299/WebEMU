from flask import Flask, request
from emulator import Emulator

import json


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

    @app.route("/compute", methods=['POST'])
    def send():
        data = request.json['data']
        code = data.splitlines()

        emu = Emulator()
        emu.run(code)
        emu.update_data()

        return{
            "registers": emu.REGISTERS,
            "memory": emu.MEMORY["data"],
            "stack": None                   # TODO: Get stack memory
        }   

    # TODO: Return errors to client

    return app

