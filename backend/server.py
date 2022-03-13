from flask import Flask, request
from cpu import uc

app = Flask(__name__)

@app.route("/", methods=['POST'])
def send():
    data = request.json['data']

    result = uc(data)

    return{
        "data": result
    }