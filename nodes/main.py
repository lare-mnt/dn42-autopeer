from flask import Flask, request, session, Response, render_template
from flask_restful import Resource, Api, reqparse
#import pandas as pd
#import ast
import json
import os
import base64
import logging
import random
import time
from functools import wraps
import subprocess

app = Flask(__name__)
api = Api(app)

# used as default value for create/update peering


class NotSpecified:
    pass


class Config (dict):
    def __init__(self, configfile: str = None):
        if configfile:
            self.configfile = configfile
        else:
            if os.path.exists("./node.config.json"):
                self.configfile = "./node.config.json"
            elif os.path.exists("./config.json"):
                self.configfile = "./config.json"
            elif os.path.exists("/etc/dn42-autopeer/node.config.json"):
                self.configfile = "/etc/dn42-autopeer/node.config.json"
            else:
                raise FileNotFoundError(
                    "no config file found in ./node.config.json, ./config.json or /etc/dn42-autopeer/config.json")
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
        print(self._config)
        if not "debug-mode" in self._config:
            self._config["debug-mode"] = False

        if not "peerings" in self._config:
            self._config["peerings"] = "./peerings"
        
        if not "wg-configs" in self._config:
            self._config["wg-configs"] = "/etc/wireguard/"
        
        if not os.path.exists(self._config["wg-configs"]):
            raise FileNotFoundError(f"specified wg-configs '{self._config['wg-configs']}' isn't a directory/doesn't exist")

        if not "wg-commands" in self._config:
            raise KeyError("wg-commands not specified")
        
        # check if required keys is a subset of the specified keys
        if not set(["enable", "disable","up","down"]) <= set(self._config["wg-commands"].keys()):
            raise KeyError("at least one of 'enable','disable','up','down' in 'wg-commands' not specified")
        
        if not "bird-peers" in self._config:
            self._config["bird-peers"] = "/etc/bird/peers/"
        if not os.path.exists(self._config["bird-peers"]):
            raise FileNotFoundError(f"specified bird-peers '{self._config['bird-peers']}' isn't a directory/doesn't exist")
        
        if not "bird-reload" in self._config:
            self._config["bird-reload"] = "birdc configure"
        
        if not "templates" in self._config:
            self._config["templates"] = "./templates"

        logging.info(self._config)


class PeeringManager:
    def __init__(self, config):
        self.__config = config
        self.__peering_file = config["peerings"]

        self.__load_peerings()

    def __load_peerings(self):
        if not os.path.exists(self.__peering_file):
            with open(self.__peering_file, "x") as p:
                json.dump({}, p)
        try:
            with open(self.__peering_file, "r") as p:
                self.peerings = json.load(p)
        except json.decoder.JSONDecodeError:
            with open(self.__peering_file, "w") as p:
                json.dump({}, p)
            with open(self.__peering_file, "r") as p:
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
    def __save_peerings(self):
        with open(self.__peering_file, "w") as p:
            json.dump(self.peerings, p, indent=4)
        self._amounts = None

    def __generate_wg_conf(self, peering: dict):
        return render_template("wireguard.template.conf", peering=peering)
    def __generate_bird_conf(self, peering: dict):
        return render_template("bgp-peer.template.conf", peering=peering)

    def __install_peering(self, mode: str, peering: dict):
        if mode == "add":
            wg_conf = self.__generate_wg_conf(peering)
            bgp_conf = self.__generate_bird_conf(peering)
            with open(f"{self.__config['wg-configs']}/dn42_{peering['ASN'][-6:] if len(peering['ASN']) >=6 else peering['ASN']}.conf", "w") as wg_file:
                wg_file.write(wg_conf)
            
            wg_enable = subprocess.run(self.__config["wg-commands"]["enable"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_enable)
            wg_up = subprocess.run(self.__config["wg-commands"]["up"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_up)
            time.sleep(5)
            with open(f"{self.__config['bird-peers']}/dn42_{peering['MNT'][:-4].lower()}_{peering['ASN'][-4:]}.conf", "w") as bgp_file:
                bgp_file.write(bgp_conf)
            bgp_reload = subprocess.run(self.__config["bird-reload"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(bgp_reload)
            
            return 200
        elif mode == "update":
            wg_conf = self.__generate_wg_conf(peering)
            bgp_conf = self.__generate_bird_conf(peering)
            with open(f"{self.__config['wg-configs']}/dn42_{peering['ASN'][-6:] if len(peering['ASN']) >=6 else peering['ASN']}.conf", "w") as wg_file:
                wg_file.write(wg_conf)
            
            wg_down = subprocess.run(self.__config["wg-commands"]["down"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_down)
            wg_up = subprocess.run(self.__config["wg-commands"]["up"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_up)
            time.sleep(5)
            with open(f"{self.__config['bird-peers']}/dn42_{peering['MNT'][:-4].lower()}_{peering['ASN'][-4:]}.conf", "w") as bgp_file:
                bgp_file.write(bgp_conf)
            bgp_reload = subprocess.run(self.__config["bird-reload"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(bgp_reload)
            
            return 200
        elif mode == "delete":
            os.remove(f"{self.__config['bird-peers']}/dn42_{peering['MNT'][:-4].lower()}_{peering['ASN'][-4:]}.conf")
            bgp_reload = subprocess.run(self.__config["bird-reload"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(bgp_reload)
            time.sleep(5)
            wg_down = subprocess.run(self.__config["wg-commands"]["down"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_down)
            wg_disable = subprocess.run(self.__config["wg-commands"]["disable"].replace("{PEERING}",peering['ASN'][-6:] if len(peering["ASN"]) >=6 else peering["ASN"]).split(" "))
            print(wg_disable)
            
            return 200

        return 405

    def get_peerings_by_asn(self, asn):
        if asn in self.peerings:
            return self.peerings[asn]
        else:
            return []

    def exists(self, asn, MNT=NotSpecified, wg_key=NotSpecified, endpoint=NotSpecified, ipv6ll=NotSpecified, ipv4=NotSpecified, ipv6=NotSpecified, bgp_mp=NotSpecified, bgp_enh=NotSpecified):
        """checks if a peerings with specific data already exists"""
        # check if mnt is specified, already exists in the database and if that mnt has the specified ASn -> if not: return False
        if not asn in self.peerings:
            return False
        selected_peerings = self.peerings[asn]
        # check if the ASn even has peerings
        if len(selected_peerings) == 0:
            return False
        for p in selected_peerings:
            if (not wg_key or p["wg_key"] == wg_key):
                return True
        return False

    def add_peering(self, MNT, ASN, wg_key, node=NotSpecified, endpoint=NotSpecified, ipv6ll=NotSpecified, ipv4=NotSpecified, ipv6=NotSpecified, bgp_mp=NotSpecified, bgp_enh=NotSpecified):
        asn = ASN
        try:
            if not asn in self.peerings:
                self.peerings[asn] = []
        except KeyError:
            self.peerings[asn] = []

        for p in self.peerings[asn]:
            if p["wg_key"] == wg_key:
                return False, 409

        new_peering = {"MNT": MNT, "ASN": asn, "node": config["nodename"], "wg_key": wg_key, "endpoint": endpoint if endpoint != NotSpecified else None,
                       "ipv6ll": ipv6ll if ipv6ll != NotSpecified else None, "ipv4": ipv4 if ipv4 != NotSpecified else None, "ipv6": ipv6 if ipv6 != NotSpecified else None,
                       "bgp_mp": bgp_mp if bgp_mp != NotSpecified else True, "bgp_enh": bgp_enh if bgp_enh != NotSpecified else True}
        self.peerings[asn].append(new_peering)

        self.__save_peerings()
        ret_code = self.__install_peering(mode="add", peering=new_peering)
        if ret_code == 200:
            return True, 201
        else:
            return False, ret_code

    def update_peering(self, ASN, wg_key, MNT=NotSpecified, node=NotSpecified, endpoint=NotSpecified, ipv6ll=NotSpecified, ipv4=NotSpecified, ipv6=NotSpecified, bgp_mp=NotSpecified, bgp_enh=NotSpecified):
        asn = ASN

        try:
            if not asn in self.peerings:
                return False, 404
        except KeyError:
            return False, 404

        success = False
        for pNr in range(len(self.peerings[asn])):
            if self.peerings[asn][pNr]["node"] == node:
                old_peering = self.peerings[asn][pNr]
                new_peering = self.peerings[asn][pNr] = {"MNT": MNT if MNT!=NotSpecified else old_peering["MNT"], "ASN": asn, "node": config["nodename"], "wg_key": wg_key,
                                                         "endpoint": endpoint if endpoint!=NotSpecified else old_peering["endpoint"], "ipv6ll": ipv6ll if ipv6ll != NotSpecified else old_peering["ipv6ll"], "ipv4": ipv4 if ipv4 != NotSpecified else old_peering["ipv4"], "ipv6": ipv6 if ipv6 != NotSpecified else old_peering["ipv6"], "bgp_mp": bgp_mp if bgp_mp != NotSpecified else old_peering["bgp_mp"], "bgp_enh": bgp_enh if bgp_enh != NotSpecified else old_peering["bgp_enh"]}
                success = True
        if not success:
            return False, 404

        self.__save_peerings()
        ret_code = self.__install_peering(mode="update", peering=new_peering)
        if ret_code == 200:
            return True, 200
        else:
            return False, ret_code

    def delete_peering(self, ASN, node, wg_key=None):
        asn = ASN
        if not self.exists(asn=asn, wg_key=wg_key):
            return False, 404
        for p in self.peerings[asn]:
            if p["node"] == node:
                if wg_key and p["wg_key"] != wg_key:
                    continue
                self.peerings[asn].remove(p)
                print(self.peerings)
                self.__save_peerings()
                ret_code = self.__install_peering(
                    mode="delete", peering=p)
                if ret_code == 200:
                    return True, 201
                else:
                    return False, ret_code
        # if nothing got found (should have been catched by self.exists)
        return False, 404


config = Config()
peerings = PeeringManager(config)


def check_ACL():
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.remote_addr in config["ACL"]:
                return f(*args, **kwargs)
            else:
                return Response(response="Unauthorized", status=401)
        return decorated
    return wrapper


class PeeringsRoute(Resource):

    @check_ACL()
    def get(self):
        parser = reqparse.RequestParser()  # initialize
        parser.add_argument('ASN', required=True)
        parser.add_argument('node', required=True, default=config["nodename"])
        parser.add_argument('wg_key')
        args = parser.parse_args()  # parse arguments to dictionary

        requested_peerings = peerings.get_peerings_by_asn(args["ASN"])
        if requested_peerings:
            return {"success": True, "ASN": args["ASN"], "peerings": requested_peerings}, 200
        else:
            return {"success": False, "ASN": args["ASN"], "error": "not found", "peerings": []}, 404

    @check_ACL()
    def post(self):
        # print(request.get_json())
        # {'MNT': 'LARE-MNT', 'ASN': '4242423035', 'node': 'node1',
        # 'wg_key': 'uM92Rks/Em2n7QLGek6OUXyGO1P/hEelMQNLlW85J2o=',
        # 'endpoint': None, 'ipv6ll': 'fe80::2', 'ipv4': None, 'ipv6': None,
        # 'bgp_mp': True, 'bgp_enh': True}
        parser = reqparse.RequestParser()  # initialize
        parser.add_argument('MNT', required=True)
        parser.add_argument('ASN', required=True)
        parser.add_argument('node', required=True, default=config["nodename"])
        parser.add_argument('wg_key', required=True)
        parser.add_argument('endpoint')
        parser.add_argument('ipv6ll')
        parser.add_argument('ipv4')
        parser.add_argument('ipv6')
        parser.add_argument('bgp_mp')
        parser.add_argument('bgp_enh')
        args = parser.parse_args()  # parse arguments to dictionary

        if not peerings.exists(asn=args["ASN"], wg_key=args["wg_key"]):
            status, code = peerings.add_peering(**args)
            if status:
                return {"success": True, "new_peering": args}, 201
            else:
                pass
        else:
            code = 409

        if code == 409:
            error_msg = "already exists"
        elif code == "50x":
            error_msg = "abc"

        return {"success": False, "error": error_msg}, code

    @check_ACL()
    def put(self):

        parser = reqparse.RequestParser()  # initialize
        parser.add_argument('MNT', required=True)
        parser.add_argument('ASN', required=True)
        parser.add_argument('node', required=True, default=config["nodename"])
        parser.add_argument('wg_key', required=True, nullable=False)
        parser.add_argument('endpoint', store_missing=False)
        parser.add_argument('ipv6ll', store_missing=False)
        parser.add_argument('ipv4', store_missing=False)
        parser.add_argument('ipv6', store_missing=False)
        parser.add_argument('bgp_mp', store_missing=False)
        parser.add_argument('bgp_enh', store_missing=False)
        args = parser.parse_args()  # parse arguments to dictionary
        print(args)
        if peerings.exists(asn=args["ASN"], wg_key=args["wg_key"]):
            ret = peerings.update_peering(**args)
            if ret:
                return {"success": True, "new_peering": args}, 200
            else:
                return {"success": False, "new_peering": args}, 500

        else:
            return {"success": False, "error": "not found"}, 404

    @check_ACL()
    def delete(self):
        parser = reqparse.RequestParser()  # initialize
        parser.add_argument('ASN', required=True, nullable=False)
        parser.add_argument('node', required=True, default=config["nodename"])
        parser.add_argument('wg_key', required=True, nullable=False)
        args = parser.parse_args()  # parse arguments to dictionary

        if peerings.exists(asn=args["ASN"], wg_key=args["wg_key"]):
            print(args)
            ret, code = peerings.delete_peering(**args)
            if ret:
                return {"success": True, "deleted": args}
        else:
            code = 404
        if code == 404:
            error_msg = "not found"
        return {"success": False, "error": error_msg}, code


api.add_resource(PeeringsRoute, '/peerings/')
app.template_folder = config["templates"]

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