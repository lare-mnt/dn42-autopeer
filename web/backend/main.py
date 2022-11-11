#! /usr/bin/env python3

from flask import Flask, Response, redirect, render_template, request, session, abort
import json, os

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
    
@app.route("/")
def index():
    print(config)
    return render_template("index.html", config=config)

def main():
    app.static_folder= config["flask-template-dir"]+"/static/"
    app.template_folder=config["flask-template-dir"]
    app.run(host=config["listen"], port=config["port"], debug=config["flask-debug"], threaded=True)


if __name__ == "__main__":
    main()