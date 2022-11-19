#! /usr/bin/env python3

from flask import Flask, Response, redirect, render_template, request, session, abort
import json, os, base64
from functools import wraps
from ipaddress import ip_address, ip_network
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

    def __contains__(self, o):
        return self._config.__contains__(o)

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
        
        if not "debug-mode" in self._config:
            self._config["debug-mode"] = False 
        if not "base-dir" in self._config:
            self._config["base-dir"] = "/"
        print(self._config)

config = Config()

def auth_required():
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not "login" in session:
                return redirect(f"{config['base-dir']}login?return={request.url}")
            else:
                return f(*args, **kwargs)
        return decorated
    return wrapper


kverifyer = kioubit_verify.AuthVerifyer(config["domain"])
@app.route("/api/auth/kverify", methods=["GET", "POST"])
def kioubit_auth():
    try: 
        params = request.args["params"]
        signature = request.args["signature"]
    except KeyError:
        return render_template("login.html", session=session,config=config,return_addr=session["return_url"], msg='"params" or "signature" missing')

    
    success, msg = kverifyer.verify(params, signature)
    try: print(base64.b64decode(params))
    except: print("invalid Base64 data provided")
    

    if success:
        session["user-data"] = msg
        session["login"] = msg['mnt']
        return redirect(session["return_url"])
    else:
        return render_template("login.html", session=session,config=config,return_addr=session["return_url"], msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "GET":
        session["return_url"] = request.args["return"] if "return" in request.args else ""
        
        return render_template("login.html", session=session, config=config, return_addr=session["return_url"])
    elif request.method == "POST" and config["debug-mode"]:
        try:
            mnt = request.form["mnt"]
            asn = request.form["asn"]
            asn = asn[2:] if asn[:1].lower() == "as" else asn
            if "allowed4" in request.form:
                allowed4 = request.form["allowed4"]
                allowed4 = allowed4.split(",") if "," in allowed4 else allowed4
            else:
                allowed4 = None
            if "allowed6" in request.form:
                allowed6 = request.form["allowed6"]
                allowed6 = allowed6.split(",") if "," in allowed6 else allowed6
            else:
                allowed6 = None
            session["user-data"] = {'asn':asn,'allowed4': allowed4, 'allowed6': allowed6,'mnt':mnt, 'authtype': "debug"}
            session["login"] = mnt
            return redirect(session["return_url"])
        except KeyError:
            msg = "not all required field were specified"
            return render_template("login.html", session=session,config=config,return_addr=session["return_url"], msg=msg)
    elif request.method == "POST" and not config["debug-mode"]:
        abort(405)
    return redirect(request.args["return"])

        
@app.route("/peerings/delete", methods=["GET","DELETE"])
@auth_required()
def peerings_delete():

    return f"{request.method} /peerings/delete?{str(request.args)}{str(request.form)}"
@app.route("/peerings/new", methods=["GET","POST"])
@auth_required()
def peerings_new():
    return render_template("peerings-new.html",  session=session,config=config)

    return f"{request.method} /peerings/new {str(request.args)}{str(request.form)}"
@app.route("/peerings", methods=["GET","POST","DELETE"])
@auth_required()
def peerings():
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings.html", config=config, selected_node=request.args["node"])
        else: 
            return render_template("peerings.html",  session=session,config=config)
    elif request.method == "POST":
        return peerings_new()
    elif request.method == "DELETE":
        return peerings_delete()
    else:
        abort(405)

@app.route("/")
def index():
    # print(config._config["nodes"])
    # for node in config["nodes"].values():
    #     print (node)
    return render_template("index.html",  session=session, config=config._config)

def main():
    app.static_folder= config["flask-template-dir"]+"/static/"
    app.template_folder=config["flask-template-dir"]
    app.secret_key = config["flask-secret-key"]
    if "production" in config and config["production"] == False:
        app.run(host=config["listen"], port=config["port"], debug=config["debug-mode"], threaded=True)
    else:
        from waitress import serve
        serve(app, host=config["listen"], port=config["port"])



if __name__ == "__main__":
    main()