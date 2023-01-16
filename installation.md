# Installation
> Note: in this configuration example the username `dn42` and "default" directories are used, if you want to use other change these in the examples.

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

to enable automatic start of this service on boot you can use this systemd .service file
```
$ cat /lib/systemd/system/dn42-autopeer-web.service
[Unit]
Description=dn42 autopeering web frontend

[Service]
# It should _not_ be run as root
User=dn42
Group=dn42
Type=simple
Restart=on-failure
RestartSec=5s
WorkingDirectory=</path/to/autopeering/>web
ExecStart=start.sh

[Install]
WantedBy=multi-user.target
```

## Nodes

1. clone repository to the node(s) or copy "nodes" directory to the nodes
2. change directory into `nodes`
3. create VirtualEnv: run `python3 -m venv venv` then `source venv/bin/activate`
4. install dependencies: `pip install -r requirement.txt`
5. create config file: 
   1. `cp node.config.example.json config.json`
   2. edit example config to represent your situation
   3. remove comments in config file
6. update the templates to represent the settings of the node
7. setup file permissions for wireguard and bird config files:
   - bird:
     - add the dn42 user to the bird group: `usermod -a -G bird dn42`
     - allow the bird group to edit config files: `chmod ug+rwx /etc/bird/peers/`
     - allow user+group bird to edit peers configs `chmod ug+rw /etc/bird/peers/ -R`
     - `chown bird:bird /etc/bird/peers -R`
   - wireguard:
     - `chown root:dn42 /etc/wireguard`
     - `chmod ug+rw /etc/wireguard/*`
     - `chmod 600 /etc/wireguard/dn42.priv`
8. allow `dn42` user to start/stop/enable/disable wireguard tunnels:
   - add the `wg-services.sh` script to `/etc/sudoers` using `visudo` <br> `Cmnd_Alias WG_SERVICES = /path/to/autopeering/nodes/wg-services.sh` <br> `dn42    ALL=(ALL) NOPASSWD:WG_SERVICES`
9.  run the server: `python backend/main.py`

to enable automatic start of this service on boot you can use this systemd .service file
```
$ cat /lib/systemd/system/dn42-autopeer-node.service
[Unit]
Description=dn42 autopeering node daemon

[Service]
# It should _not_ be run as root
User=dn42
Group=dn42
Type=simple
Restart=on-failure
RestartSec=5s
WorkingDirectory=</path/to/autopeering>/nodes
ExecStart=start.sh

[Install]
WantedBy=multi-user.target
```