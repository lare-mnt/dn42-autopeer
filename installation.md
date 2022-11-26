# Installation

## Server

1. clone repository to the main server
2. change into `web`
3. create VirtualEnv: run `python3 -m venv venv` then `source venv/bin/activate`
4. install dependencies: `pip install -r requirement.txt`
5. create config file: 
   1. `cp backend/config.example.json config.json`
   2. edit example config to represent your situation
   3. remove comments in config file
6. run the server: `python backend/main.py`

## Nodes
#todo