import json
import os
import base64
import logging
import random
import threading
import requests

class NodeCommunicator:

    def __init__(self, name:str, config):
        self.name = name
        self.__config = config
        self.__api_addr = config["api-con"]
    
    def update(self, action:str, updated_peering:dict):
        print(requests.api.post(self.__api_addr+"peerings", json=updated_peering).content)
        input()

class PeeringManager:

    def __init__(self, config):
        self.__config = config
        self.__peering_file = config["peerings"]

        self.__load_peerings()

        self._nodes = {}
        for node in self.__config["nodes"]:
            self._nodes[node] = NodeCommunicator(name=node, config=self.__config["nodes"][node])
        
        self._amounts = None
        self._threads = []

    def __load_peerings(self):
        if not os.path.exists(self.__peering_file):
            with open(self.__peering_file, "x") as p:
                json.dump({"mnter": {}, "asn": {}}, p)
        try:
            with open(self.__peering_file, "r") as p:
                self.peerings = json.load(p)
        except json.decoder.JSONDecodeError:
            with open(self.__peering_file, "w") as p:
                json.dump({"mnter": {}, "asn": {}}, p)
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
    def _save_peerings(self):
        with open(self.__peering_file, "w") as p:
            json.dump(self.peerings, p, indent=4)
        self._amounts = None

    def _update_nodes(self, action:str, peering, new_peering=None):
        """mode: "add","update","delete
        peering: peering to send to node (included in peering)
        new_peering: if mode=="update" the new peering to update to
        """
        if peering["node"] in self._nodes:
            thread = threading.Thread(target=self._nodes[peering["node"]].update,kwargs={"action":action,"updated_peering":peering if not new_peering else new_peering,})
            thread.start()
            self._threads.append(thread)
        
        else: return False

    def _update_amounts(self):
        __new = {}
        for asn in self.peerings["asn"]:
            for peering in self.peerings["asn"][asn]:
                if not peering["node"] in __new:
                    __new[peering["node"]] = 0
                __new[peering["node"]] += 1
        self._amounts = __new


    def amount_by_node(self, node_name: str):
        if self._amounts ==None:
            self._update_amounts()
        try:
            return self._amounts[node_name]
        except KeyError:
            return 0
    def exists(self, asn, node, mnt=None, wg_key=None, endpoint=None, ipv6ll=None, ipv4=None, ipv6=None, bgp_mp=True, bgp_enh=True):
        """checks if a peerings with specific data already exists"""
        # check if mnt is specified, already exists in the database and if that mnt has the specified ASn -> if not: return False
        if mnt and not (mnt in self.peerings["mnter"] and asn in self.peerings["mnter"][mnt]):
            return False
        selected_peerings = self.peerings["asn"][asn]
        # check if the ASn even has peerings
        if len(selected_peerings) == 0:
            return False
        for p in selected_peerings:
            if p["node"] == node:
                if (not wg_key or p["wg_key"] == wg_key) and (not endpoint or p["endpoint"] == endpoint) \
                        and (not ipv6ll or p["ipv6ll"] == ipv6ll) and (not ipv4 or p["ipv4"] == ipv4) and (not ipv6 or p["ipv6"] == ipv6)\
                        and (not bgp_mp or p["bgp_mp"] == bgp_mp) and (not bgp_enh or p["bgp_enh"] == bgp_enh):
                    return True
        return False

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

    def add_peering(self, asn, node, mnt, wg_key, endpoint=None, ipv6ll=None, ipv4=None, ipv6=None, bgp_mp=True, bgp_enh=True):
        # check if this MNT already has a/this asn
        try:
            if not asn in self.peerings["mnter"][mnt]:
                # ... and add it if it hasn't
                self.peerings[mnt].append(asn)
        except KeyError:
            # ... and cerate it if it doesn't have any yet
            self.peerings["mnter"][mnt] = [asn]
        try:
            if not asn in self.peerings["asn"]:
                self.peerings["asn"][asn] = []
        except KeyError:
            self.peerings["asn"][asn] = []

        # deny more than one peering per ASN to one node
        for peering in self.peerings["asn"][asn]:
            if peering["node"] == node:
                return False

        self.peerings["asn"][asn].append({"MNT": mnt, "ASN": asn, "node": node, "wg_key": wg_key, "endpoint": endpoint,
                                         "ipv6ll": ipv6ll, "ipv4": ipv4, "ipv6": ipv6, "bgp_mp": bgp_mp, "bgp_enh": bgp_enh})

        self._save_peerings()
        return True

    def update_peering(self, asn, node, mnt, wg_key, endpoint=None, ipv6ll=None, ipv4=None, ipv6=None, bgp_mp=True, bgp_enh=True):
        # check if this MNT already has a/this asn
        try:
            if not asn in self.peerings["mnter"][mnt]:
                # ... and add it if it hasn't
                self.peerings[mnt].append(asn)
        except KeyError:
            # ... and cerate it if it doesn't have any yet
            self.peerings["mnter"][mnt] = [asn]
        try:
            if not asn in self.peerings["asn"]:
                return False
        except KeyError:
            return False

        success = False
        for pNr in range(len(self.peerings["asn"][asn])):
            if self.peerings["asn"][asn][pNr]["node"] == node:
                old_peering = self.peerings["asn"][asn][pNr]
                new_peering = self.peerings["asn"][asn][pNr] = {"MNT": mnt, "ASN": asn, "node": node, "wg_key": wg_key,
                                                  "endpoint": endpoint, "ipv6ll": ipv6ll, "ipv4": ipv4, "ipv6": ipv6, "bgp_mp": bgp_mp, "bgp_enh": bgp_enh}
                success = True
        if not success:
            return False
        
        self._save_peerings()
        self._update_nodes("update", old_peering, new_peering=new_peering)
        return True

    def delete_peering(self, asn, node, mnt, wg_key=None):
        if not self.exists(asn, node, mnt=mnt, wg_key=wg_key):
            return False
        for p in self.peerings["asn"][asn]:
            if p["node"] == node:
                if wg_key and p["wg_key"] != wg_key:
                    continue
                self.peerings["asn"][asn].remove(p)
                self._save_peerings()
                return True
        # if nothing got found (should have been catched by self.exists)
        return False
