#! /usr/bin/env python3

from flask import Flask, Response, redirect, render_template, request, session, abort
import werkzeug.exceptions as werkzeug_exceptions
import json, os, base64, logging, random
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
        self._load_config()
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
     
    def _load_config(self):
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
        
        if not "peerings-data" in self._config:
            self._config["peering-data"] = "./peerings"
        logging.info(self._config)

class PeeringManager:

    def __init__(self, peerings_file):
        self._peering_file = peerings_file

        self._load_peerings()

    def _load_peerings(self):
        if not os.path.exists(self._peering_file):
            with open(self._peering_file, "x") as p: 
                json.dump({"mnter":{},"asn":{}}, p)
        try:       
            with open(self._peering_file,"r") as p:
                self.peerings = json.load(p)
        except json.decoder.JSONDecodeError:
            with open(self._peering_file, "w") as p: 
                json.dump({"mnter":{},"asn":{}}, p)
            with open(self._peering_file,"r") as p:
                self.peerings = json.load(p)

        # self.peerings = {}
        # missing_peerings = False
        # for peering in self._peerings:
        #     if os.path.exists(f"{self._peering_dir}/{peering}.json"):
        #         with open(f"{self._peering_dir}/{peering}.json") as peer_cfg:
        #             self.peerings[peering] = json.load(peer_cfg)
        #     else:
        #         logging.warning(f"peering with id {peering} doesn't exist. removing reference in `{self._peering_dir}/peerings.json`")
        #         self._peerings.remove(peering)
        #         missing_peerings = True
        # if missing_peerings:
        #     with open(f"{self._peering_dir}/peerings.json","w") as p:
        #         json.dump(self._peerings, p, indent=4)
    def _save_peerings(self):
        with open(self._peering_file, "w") as p:
            json.dump(self.peerings, p, indent=4)

    def get_peerings_by_mnt(self, mnt):
        # print(self.peerings)
        try:
            out = []
            for asn in self.peerings["mnter"][mnt]:
                try:
                    for peering in self.peerings["asn"][asn]:
                        out.append(peering)
                except KeyError as e:
                    pass
            return out
        except KeyError:
            return {}

    def add_peering(self, mnt, asn, node, wg_key, endpoint=None, ipv6ll=None, ipv4=None, ipv6=None):
        try:
            if not asn in self.peerings["mnter"][mnt]:
                self.peerings[mnt].append(asn)
        except KeyError:
            self.peerings["mnter"][mnt] = [asn]
        try:
            if not asn in self.peerings["asn"]:
                self.peerings["asn"][asn] = []
        except KeyError:
            self.peerings["asn"][asn] = []
        
        # deny more than one peering per ASN to one node 
        for peering in self.peerings["asn"][asn]:
            if peering["node"] == node: return False
        self.peerings["asn"][asn].append({"MNT":mnt,"ASN":asn, "node": node, "wg_key":wg_key, "endpoint": endpoint,"ipv6ll":ipv6ll,"ipv4":ipv4,"ipv6":ipv6})

        self._save_peerings()
        return True
        

config = Config()
peerings = PeeringManager(config["peerings"])
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
    try: logging.debug(base64.b64decode(params))
    except: logging.debug("invalid Base64 data provided")
    

    if success:
        session["user-data"] = msg
        session["login"] = msg['mnt']
        try:
            return redirect(session["return_url"])
        except KeyError:
            return redirect(f"{config['base-dir']}peerings")
    else:
        try:
            return render_template("login.html", session=session,config=config,return_addr=session["return_url"], msg=msg)
        except KeyError:
            return render_template("login.html", session=session,config=config,return_addr=f"{config['base-dir']}peerings", msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login",methods=["GET","POST"])
def login():
    print(session)
    if request.method == "GET":
        session["return_url"] = request.args["return"] if "return" in request.args else ""
        
        return render_template("login.html", session=session, config=config, return_addr=session["return_url"])
    elif request.method == "POST" and config["debug-mode"]:
        try:
            print(request.form)
            if request.form["theanswer"] != "42":
                msg = "what is the answer for everything?"
                return render_template("login.html", session=session,config=config,return_addr=session["return_url"], msg=msg)
            mnt = request.form["mnt"]
            asn = request.form["asn"]
            asn = asn[2:] if asn[:2].lower() == "as" else asn
            if "allowed4" in request.form:
                allowed4 = request.form["allowed4"]
                # allowed4 = allowed4.split(",") if "," in allowed4 else allowed4
            else:
                allowed4 = None
            if "allowed6" in request.form:
                allowed6 = request.form["allowed6"]
                # allowed6 = allowed6.split(",") if "," in allowed6 else allowed6
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
        
@app.route("/peerings/edit", methods=["GET","POST"])
@auth_required()
def peerings_edit():
    print(session)
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings-new.html", config=config, selected_node=request.args["node"], peerings=peerings)
        else: 
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings)
    elif request.method == "POST":

        return f"{request.method} /peerings/edit?{str(request.args)}{str(request.form)}"
@app.route("/peerings/new", methods=["GET","POST"])
@auth_required()
def peerings_new():
    print(session)
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings-new.html", config=config, selected_node=request.args["node"], peerings=peerings)
        else: 
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings)
    elif request.method == "POST":
        print(request.args)
        print(request.form)
        if not "node" in request.args or not request.args["node"]:
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="no node specified, please click one of the buttons above")

        new_peering = {}
        # errors = 0
        
        ## check if all required (and enabled) options are specified
        try:
            new_peering["peer-asn"] = session["user-data"]["asn"]
            new_peering["peer-wgkey"] = request.form["peer-wgkey"]
            if  request.form["peer-endpoint-enabled"] == "on":
                new_peering["peer-endpoint"] = request.form["peer-endpoint"]
                if new_peering["peer-endpoint"] == "":
                    raise ValueError("peer-endpoint")
            else:
                new_peering["peer-endpoint"] = None
            
            if "peer-v6ll-enabled" in request.form and request.form["peer-v6ll-enabled"] == "on":
                new_peering["peer-v6ll"] = request.form["peer-v6ll"]
                if new_peering["peer-v6ll"] == "":
                    raise ValueError("peer-v6ll")
            else:
                new_peering["peer-v6ll"] = None
            if "peer-v4-enabled" in request.form and request.form["peer-v4-enabled"] == "on":
                new_peering["peer-v4"] = request.form["peer-v4"]
                if new_peering["peer-v4"] == "":
                    raise ValueError("peer-v4")
            else:
                new_peering["peer-v4"] = None
            if "peer-v6-enabled" in request.form and request.form["peer-v6-enabled"] == "on":
                new_peering["peer-v6"] = request.form["peer-v6"]
                if new_peering["peer-v6"] == "":
                    raise ValueError("peer-v6")
            else:
                new_peering["peer-v6"] = None
            #new_peering[""] = request.form["peer-wgkey"]
        except ValueError as e:
            print(f"error: {e.args}")
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="at least one of the required/enabled fields was not filled out"), 400

        print(new_peering)

        ## check wireguard key
        wg_key_invalid = False
        if len(new_peering["peer-wgkey"]) != 44:
            wg_key_invalid = True
        try:
            base64.b64decode(new_peering["peer-wgkey"])
        except:
            wg_key_invalid = True
        if wg_key_invalid: 
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="invalid wireguard Key"), 400

        ## check endpoint 
        if new_peering["peer-endpoint"]:
            if not new_peering["peer-endpoint"].split(":")[-1].isnumeric():
                return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="no port number in endpoint"), 400
            elif len(new_peering["peer-endpoint"].split(":")) < 2 and not "." in new_peering["peer-endpoint"]:
                return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="endpoint doesn't look like a ip address or fqdn"), 400

        ## check if at least one ip is specified/enabled
        try:
            if not (new_peering["peer-v6ll"] or new_peering["peer-v4"] or new_peering["peer-v6"]):
                return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="at least one of the ip addresses must be enabled and specified"), 400
        except KeyError:
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="one of the values isn't valid"), 400

        ## check if supplied ip addresses are valid
        try:
            if new_peering["peer-v6ll"]:
                ipv6ll = ip_address(new_peering["peer-v6ll"])
                if not ipv6ll.version == 6: raise ValueError()
                if not ipv6ll.is_link_local: raise ValueError()
            if new_peering["peer-v4"]:
                ipv4 = ip_address(new_peering["peer-v4"])
                if not ipv4.version == 4: raise ValueError()
                if ipv4.is_link_local:
                    pass
                elif ipv4.is_private:
                    if not (ipv4.compressed.startswith("172.2") or ipv4.compressed.startswith("10.")):
                        raise ValueError()
                    is_in_allowed = False
                    if session["user-data"]["allowed4"]:
                        for allowed4 in session["user-data"]["allowed4"].split(","):
                            if ipv4 in ip_network(allowed4):
                                is_in_allowed = True
                    if not is_in_allowed:
                        return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="supplied ipv4 addr not in allowed ip range"), 400
                else: raise ValueError()
            if new_peering["peer-v6"]:
                ipv6 = ip_address(new_peering["peer-v6"])
                if not ipv6.version == 6: raise ValueError()
                if not ipv6.is_private: raise ValueError()
                if ipv6.is_link_local: raise ValueError()
                is_in_allowed = False
                if session["user-data"]["allowed6"]:
                    for allowed6 in session["user-data"]["allowed6"].split(","):
                        if ipv6 in ip_network(allowed6):
                            is_in_allowed = True
                if not is_in_allowed:
                    return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="supplied ipv6 addr not in allowed ip range"), 400
            
        except ValueError:
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="invalid ip address(es) supplied"), 400

        if not peerings.add_peering(session["user-data"]["mnt"], session["user-data"]["asn"], request.args["node"], new_peering["peer-wgkey"], new_peering["peer-endpoint"], new_peering["peer-v6ll"], new_peering["peer-v4"], new_peering["peer-v6"]):
            return render_template("peerings-new.html",  session=session,config=config, peerings=peerings, msg="this ASN already has a peering with the requested node"), 400

        return redirect(f"{config['base-dir']}peerings")
        return """<div>creating peerings is not (yet) implemented</div><div><a href="../">return</a>"""
        return f"{request.method} /peerings/new {str(request.args)}{str(request.form)}"
@app.route("/peerings", methods=["GET","POST","DELETE"])
@auth_required()
def peerings_view():
    print(session)
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings.html", config=config, selected_node=request.args["node"], peerings=peerings)
        else: 
            return render_template("peerings.html",  session=session,config=config, peerings=peerings)
    elif request.method == "POST":
        return peerings_new()
    elif request.method == "DELETE":
        return peerings_delete()
    else:
        abort(405)

@app.route("/")
def index():
    print(session)
    # print(config._config["nodes"])
    # for node in config["nodes"].values():
    #     print (node)
    return render_template("index.html",  session=session, config=config._config)

def main():
    app.static_folder= config["flask-template-dir"]+"/static/"
    app.template_folder=config["flask-template-dir"]
    app.secret_key = config["flask-secret-key"]
    if "production" in config and config["production"] == False:
        logging.getLogger(__name__).setLevel(0)
        app.run(host=config["listen"], port=config["port"], debug=config["debug-mode"], threaded=True)
    else:
        from waitress import serve
        logging.getLogger(__name__).setLevel(logging.INFO)
        serve(app, host=config["listen"], port=config["port"])



if __name__ == "__main__":
    main()