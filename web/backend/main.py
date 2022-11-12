#! /usr/bin/env python3

from flask import Flask, Response, redirect, render_template, request, session, abort
import json, os, base64
from functools import wraps

import kioubit_verify

app = Flask(__name__)

class Config (dict):
    def __init__(self, configfile:str = None):
        if configfile:
            self.configfile = configfile
        else:
            if os.path.exists("./config.json"): self.configfile = "./config.json"
            elif os.path.exists("/etc/dn42-autopeer/config.json"): self.configfile = "/etc/dn42-autopeer/config,json"
            else: raise FileNotFoundError("no config file found in ./config.json or /etc/dn42-autopeer/config.json")
        self.load_config()
        self.keys = self._config.keys
        #self.__getitem__ = self._config.__getitem__
        super().__init__(self)

    def __delitem__(self, v):
        raise NotImplementedError()
        super().__delitem__(self,v)
    def __getitem__(self, k):
        return self._config[k]
    def load_config(self):
        with open(self.configfile) as cf:
            try:
                self._config = json.load(cf)
            except json.decoder.JSONDecodeError:
                raise SyntaxError(f"no valid JSON found in '{cf.name}'")
        
        if not "flask-template-dir" in self._config:
            self._config["flask-template-dir"] = "../frontend" 
        
        if not "flask-debug" in self._config:
            self._config["flask-debug"] = False 

        print(self._config)

config = Config()

def auth_required():
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not "logged_in" in session:
                return redirect(f"login?return={request.url}")
            else:
                return f(*args, **kwargs)
        return decorated
    return wrapper


kverifyer = kioubit_verify.AuthVerifyer(config["domain"])
@app.route("/api/auth/kverify", methods=["GET", "POST"])
def kioubit_auth():
    params = request.args["params"]
    signature = request.args["signature"]
    print(base64.b64decode(params))
    return str(kverifyer.verify(params, signature))


@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "GET":
        session["return_url"] = request.args["return"]
        return render_template("login.html", config=config, return_addr=request.args["return"])

    #elif request.method == "POST":
        
@app.route("/peer", methods=["GET","POST"])
@auth_required()
def peer():
    return request.args
    
@app.route("/")
def index():
    # print(config._config["nodes"])
    # for node in config["nodes"].values():
    #     print (node)
    return render_template("index.html", config=config._config)

def main():
    app.static_folder= config["flask-template-dir"]+"/static/"
    app.template_folder=config["flask-template-dir"]
    app.secret_key = config["flask-secret-key"]
    app.run(host=config["listen"], port=config["port"], debug=config["flask-debug"], threaded=True)


if __name__ == "__main__":
    main()