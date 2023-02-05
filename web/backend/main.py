#! /usr/bin/env python3

from flask import Flask, Response, redirect, render_template, request, session, abort
import werkzeug.exceptions as werkzeug_exceptions
import json
import os
import base64
import logging
import random
from functools import wraps
from ipaddress import ip_address, ip_network, IPv4Network, IPv6Network
import kioubit_verify
from peering_manager import PeeringManager

app = Flask(__name__)


class Config (dict):
    def __init__(self, configfile: str = None):
        if configfile:
            self.configfile = configfile
        else:
            if os.path.exists("./config.json"):
                self.configfile = "./config.json"
            elif os.path.exists("/etc/dn42-autopeer/config.json"):
                self.configfile = "/etc/dn42-autopeer/config.json"
            else:
                raise FileNotFoundError(
                    "no config file found in ./config.json or /etc/dn42-autopeer/config.json")
        self._load_config()
        self.keys = self._config.keys
        #self.__getitem__ = self._config.__getitem__
        super().__init__(self)

    def __contains__(self, o):
        return self._config.__contains__(o)

    def __delitem__(self, v):
        raise NotImplementedError()
        super().__delitem__(self, v)

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
        
        if not "nodes" in self._config:
            self,_config = {}
        for node in self._config["nodes"]:
            if not "capacity" in self._config["nodes"][node]:
                self._config["nodes"][node]["capacity"] = -1
        
        logging.info(self._config)



config = Config()
peerings = PeeringManager(config)
kverifyer = kioubit_verify.AuthVerifyer(config["domain"])


def check_peering_data(form):
    new_peering = {}
    # errors = 0

    # check if all required (and enabled) options are specified
    try:
        new_peering["peer-asn"] = session["user-data"]["asn"]
        new_peering["peer-wgkey"] = form["peer-wgkey"]
        if "peer-endpoint-enabled" in form and form["peer-endpoint-enabled"] == "on":
            new_peering["peer-endpoint"] = form["peer-endpoint"]
            if new_peering["peer-endpoint"] == "":
                raise ValueError("peer-endpoint")
        else:
            new_peering["peer-endpoint"] = None

        if "peer-v6ll-enabled" in form and form["peer-v6ll-enabled"] == "on":
            new_peering["peer-v6ll"] = form["peer-v6ll"]
            if new_peering["peer-v6ll"] == "":
                raise ValueError("peer-v6ll")
        else:
            new_peering["peer-v6ll"] = None
        if "peer-v4-enabled" in form and form["peer-v4-enabled"] == "on":
            new_peering["peer-v4"] = form["peer-v4"]
            if new_peering["peer-v4"] == "":
                raise ValueError("peer-v4")
        else:
            new_peering["peer-v4"] = None
        if "peer-v6-enabled" in form and form["peer-v6-enabled"] == "on":
            new_peering["peer-v6"] = form["peer-v6"]
            if new_peering["peer-v6"] == "":
                raise ValueError("peer-v6")
        else:
            new_peering["peer-v6"] = None
        new_peering["bgp-mp"] = form["bgp-multi-protocol"] if "bgp-multi-protocol" in form else "off"
        new_peering["bgp-mp"] = True if new_peering["bgp-mp"] == "on" else False
        new_peering["bgp-enh"] = form["bgp-extended-next-hop"] if "bgp-extended-next-hop" in form else "off"
        new_peering["bgp-enh"] = True if new_peering["bgp-enh"] == "on" else False
        #new_peering[""] = form["peer-wgkey"]
    except ValueError as e:
        print(f"error: {e.args}")
        return False, "at least one of the required/enabled fields was not filled out"

    print(new_peering)

    # check wireguard key
    wg_key_invalid = False
    if len(new_peering["peer-wgkey"]) != 44:
        wg_key_invalid = True
    try:
        base64.b64decode(new_peering["peer-wgkey"])
    except:
        wg_key_invalid = True
    if wg_key_invalid:
        return False, "invalid wireguard Key"

    # check endpoint
    if new_peering["peer-endpoint"]:
        if not new_peering["peer-endpoint"].split(":")[-1].isnumeric():
            return False, "no port number in endpoint"
        elif len(new_peering["peer-endpoint"].split(":")) < 2 and not "." in new_peering["peer-endpoint"]:
            return False, "endpoint doesn't look like a ip address or fqdn"

    # check if at least one ip is specified/enabled
    try:
        if not (new_peering["peer-v6ll"] or new_peering["peer-v4"] or new_peering["peer-v6"]):
            return False, "at least one of the ip addresses must be enabled and specified"
    except KeyError:
        return False, "one of the values isn't valid"

    # check if supplied ip addresses are valid
    try:
        if new_peering["peer-v6ll"]:
            ipv6ll = ip_address(new_peering["peer-v6ll"])
            if not ipv6ll.version == 6:
                raise ValueError()
            if not ipv6ll.is_link_local:
                raise ValueError()
        if new_peering["peer-v4"]:
            ipv4 = ip_address(new_peering["peer-v4"])
            if not ipv4.version == 4:
                raise ValueError()
            if ipv4.is_link_local:
                pass
            elif ipv4.is_private:
                if not (ipv4.compressed.startswith("172.2") or ipv4.compressed.startswith("10.")):
                    raise ValueError()
                is_in_allowed = False
                if session["user-data"]["allowed4"]:
                    if not isinstance(session["user-data"]["allowed4"],tuple):
                        allowed4 = session["user-data"]["allowed4"]
                        if ipv4 in ip_network(allowed4):
                            is_in_allowed = True
                    else:
                        for allowed4 in session["user-data"]["allowed4"]:
                            if ipv4 in ip_network(allowed4):
                                is_in_allowed = True
                if not is_in_allowed:
                    return False, "supplied ipv4 addr not in allowed ip range"
            else:
                raise ValueError()
        if new_peering["peer-v6"]:
            ipv6 = ip_address(new_peering["peer-v6"])
            if not ipv6.version == 6:
                raise ValueError()
            if not ipv6.is_private:
                raise ValueError()
            if ipv6.is_link_local:
                raise ValueError()
            is_in_allowed = False
            if session["user-data"]["allowed6"]:
                if not isinstance(session["user-data"]["allowed6"],tuple):
                    allowed6 = session["user-data"]["allowed6"]
                    if ipv6 in ip_network(allowed6):
                        is_in_allowed = True
                else:
                    for allowed6 in session["user-data"]["allowed6"]:
                        if ipv6 in ip_network(allowed6):
                            is_in_allowed = True
            if not is_in_allowed:
                return False, "supplied ipv6 addr not in allowed ip range"
    except ValueError as e:
        print(e)
        return False, "invalid ip address(es) supplied"

    # check bgp options
    try:
        if new_peering["bgp-mp"] == False and new_peering["bgp-enh"] == True:
            return False, "extended next hop requires multiprotocol bgp"
        if new_peering["bgp-mp"] == False:
            if not (new_peering["peer-v4"] and (new_peering["peer-v6"] or new_peering["peer-v6ll"])):
                return False, "ipv4 and ipv6 addresses required when not having MP-BGP"
    except ValueError:
        pass
    return True, new_peering


def auth_required():
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not "login" in session:
                request_url = f"{config['base-dir']}{request.full_path}".replace("//", "/")
                return redirect(f"{config['base-dir']}login?return={request_url}")
            else:
                return f(*args, **kwargs)
        return decorated
    return wrapper


@app.route("/api/auth/kverify", methods=["GET", "POST"])
def kioubit_auth():
    try:
        params = request.args["params"]
        signature = request.args["signature"]
    except KeyError:
        return render_template("login.html", session=session, config=config, return_addr=session["return_url"], msg='"params" or "signature" missing')

    success, msg = kverifyer.verify(params, signature)
    try:
        logging.debug(base64.b64decode(params))
    except:
        logging.debug("invalid Base64 data provided")

    if success:
        session["user-data"] = msg
        session["login"] = msg['mnt']
        try:
            return redirect(session["return_url"])
        except KeyError:
            return redirect(f"{config['base-dir']}peerings")
    else:
        try:
            return render_template("login.html", session=session, config=config, return_addr=session["return_url"], msg=msg)
        except KeyError:
            return render_template("login.html", session=session, config=config, return_addr=f"{config['base-dir']}peerings", msg=msg)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(config["base-dir"])


@app.route("/login", methods=["GET", "POST"])
def login():
    print(session)
    if request.method == "GET":
        session["return_url"] = request.args["return"] if "return" in request.args else ""

        return render_template("login.html", session=session, config=config, return_addr=session["return_url"])
    elif request.method == "POST" and config["debug-mode"]:
        try:
            print(request.form)
            if request.form["theanswer"] != "42":
                msg = """what is the answer for everything? <a href="https://en.wikipedia.org/wiki/42_(answer)">hint</a>"""
                return render_template("login.html", session=session, config=config, return_addr=session["return_url"], msg=msg)
            mnt = request.form["mnt"]
            if not mnt.upper().endswith("-MNT"):
                raise ValueError
            asn = request.form["asn"]
            asn = asn[2:] if asn[:2].lower() == "as" else asn
            int(asn)
            if "allowed4" in request.form:
                allowed4 = request.form["allowed4"]
                v4_ranges = allowed4.split(",") if "," in allowed4 else [allowed4]
                for v4_range in v4_ranges:
                    IPv4Network(v4_range)
            else:
                allowed4 = None
            if "allowed6" in request.form:
                allowed6 = request.form["allowed6"]
                v6_ranges = allowed6.split(",") if "," in allowed6 else [allowed6]
                for v6_range in v6_ranges:
                    IPv6Network(v6_range)
            else:
                allowed6 = None
            session["user-data"] = {'asn': asn, 'allowed4': allowed4,
                                    'allowed6': allowed6, 'mnt': mnt, 'authtype': "debug"}
            session["login"] = mnt
            return redirect(session["return_url"])
        except ValueError:
            msg = "at least one of the values provided is wrong/invalid"
            return render_template("login.html", session=session, config=config, return_addr=session["return_url"], msg=msg)
        except KeyError:
            msg = "not all required field were specified"
            return render_template("login.html", session=session, config=config, return_addr=session["return_url"], msg=msg)
    elif request.method == "POST" and not config["debug-mode"]:
        abort(405)
    return redirect(request.args["return"])


@app.route("/peerings/delete", methods=["GET", "POST", "DELETE"])
@auth_required()
def peerings_delete():

    if request.method == "GET":
        return render_template("peerings-delete.html", session=session, config=config, request_args=request.args)
        return f"{request.method} /peerings/delete?{str(request.args)}{str(request.form)}"
    elif request.method in ["POST", "DELETE"]:
        if not request.form["confirm"] == "on":
            return render_template("peerings-delete.html", session=session, config=config, request_args=request.args, msg="you have to confirm the deletion first")
        if not peerings.exists(request.args["asn"], request.args["node"], mnt=session["login"]):
            return render_template("peerings-delete.html", session=session, config=config, request_args=request.args, msg="the peering you requested to delete doesn't exist (anymore) or you are not authorized to delete it")
        print(str(request))
        if not peerings.delete_peering(request.args["asn"], request.args["node"], mnt=session["login"]):
            return render_template("peerings-delete.html", session=session, config=config, request_args=request.args, msg="deletion of the peering requested failed, maybe you are not authorized or that peering doesn't exist")
        session["msg"] = {"msg": "peer-del",
                          "node": request.args["node"], "asn": request.args["asn"]}
        return redirect("../peerings")
        return f"{request.method} /peerings/delete {request.args} {request.form}"


@app.route("/peerings/edit", methods=["GET", "POST"])
@auth_required()
def peerings_edit():
    print(session)
    if request.method == "GET":
        if not "node" in request.args or not request.args["node"]:
            return render_template("peerings-edit.html",  session=session, config=config, peerings=peerings, msg="no peering selected, please click one of the buttons above")
        mnt_peerings = peerings.get_peerings_by_mnt(session["login"])
        # print(mnt_peerings)
        if "node" in request.args and request.args["node"] in config["nodes"]:
            selected_peering = None
            for p in mnt_peerings:
                if p["node"] == request.args["node"] and p["ASN"] == request.args["asn"]:
                    selected_peering = p
                    print(p)
                    break
            return render_template("peerings-edit.html", session=session, config=config, mnt_peerings=mnt_peerings, selected_peering=selected_peering, selected_node=selected_peering["node"])
        else:
            print(request.args)
            return render_template("peerings-edit.html", session=session, config=config, mnt_peerings=mnt_peerings, selected_peering=None)
    elif request.method == "POST":
        print(request.args)
        print(request.form)
        if not "node" in request.args or not request.args["node"]:
            return render_template("peerings-edit.html",  session=session, config=config, peerings=peerings, msg="no peering selected, please click one of the buttons above")

        peering_valid, peering_or_msg = check_peering_data(request.form)
        print(peering_valid)
        print(peering_or_msg)
        selected_peering = None
        mnt_peerings = peerings.get_peerings_by_mnt(session["login"])
        for p in mnt_peerings:
            if p["node"] == request.args["node"] and p["ASN"] == request.args["asn"]:
                selected_peering = p
                print(p)
                break
        if not peering_valid:
            return render_template("peerings-edit.html",  session=session, config=config, peerings=peerings, msg=peering_or_msg, selected_peering=selected_peering), 400
        if not peerings.update_peering(session["user-data"]["asn"], request.args["node"], session["login"], peering_or_msg["peer-wgkey"], peering_or_msg["peer-endpoint"], peering_or_msg["peer-v6ll"], peering_or_msg["peer-v4"], peering_or_msg["peer-v6"], peering_or_msg["bgp-mp"], peering_or_msg["bgp-enh"]):
            return render_template("peerings-edit.html",  session=session, config=config, peerings=peerings, msg="such a peering doesn't exist(yet)", selected_peering=selected_peering), 400

        return redirect(f"{config['base-dir']}peerings")
        return f"{request.method} /peerings/edit?{str(request.args)}{str(request.form)}"


@app.route("/peerings/new", methods=["GET", "POST"])
@auth_required()
def peerings_new():
    print(session)
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings-new.html", config=config, selected_node=request.args["node"], peerings=peerings)
        else:
            return render_template("peerings-new.html",  session=session, config=config, peerings=peerings)
    elif request.method == "POST":
        print(request.args)
        print(request.form)
        if not "node" in request.args or not request.args["node"]:
            return render_template("peerings-new.html",  session=session, config=config, peerings=peerings, msg="no node specified, please click one of the buttons above")

        peering_valid, peering_or_msg = check_peering_data(request.form)

        if not peering_valid:
            return render_template("peerings-new.html",  session=session, config=config, peerings=peerings, msg=peering_or_msg), 400
        if not peerings.add_peering(session["user-data"]["asn"], request.args["node"], session["login"], peering_or_msg["peer-wgkey"], peering_or_msg["peer-endpoint"], peering_or_msg["peer-v6ll"], peering_or_msg["peer-v4"], peering_or_msg["peer-v6"], peering_or_msg["bgp-mp"], peering_or_msg["bgp-enh"]):
            return render_template("peerings-new.html",  session=session, config=config, peerings=peerings, msg="this ASN already has a peering with the requested node"), 400

        return redirect(f"{config['base-dir']}peerings")


@app.route("/peerings", methods=["GET", "POST", "DELETE"])
@auth_required()
def peerings_view():
    print(session)
    if request.method == "GET":
        if "node" in request.args and request.args["node"] in config["nodes"]:
            return render_template("peerings.html", config=config, selected_node=request.args["node"], peerings=peerings)
        else:
            return render_template("peerings.html",  session=session, config=config, peerings=peerings)
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
    return render_template("index.html",  session=session, config=config, peerings = peerings)


app.static_folder = config["flask-template-dir"]+"/static/"
app.template_folder = config["flask-template-dir"]
app.secret_key = config["flask-secret-key"]
def main():
    if "production" in config and config["production"] == False:
        logging.getLogger(__name__).setLevel(0)
        app.run(host=config["listen"], port=config["port"],
                debug=config["debug-mode"], threaded=True)
    else:
        from waitress import serve
        logging.getLogger(__name__).setLevel(logging.INFO)
        serve(app, host=config["listen"], port=config["port"])


if __name__ == "__main__":
    main()
