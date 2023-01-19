# lare's autopeering implementation

This is my (LARE-MNT) implementation of an auto peering system

It consists of two parts:
1. the "server" 
   - handling user auth (via kioubit) 
   - add/edit/delete peerings
   - communicate new/update peerings with nodes
2. the "nodes daemon"
   - reveives new/updated peering configs from the "server" 


## Installation

see [installation.md](installation.md)