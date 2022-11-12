#! /usr/bin/env python3

#import OpenSSL
#from OpenSSL.crypto import load_publickey, FILETYPE_PEM, X509
#from OpenSSL.crypto import verify as OpenSSL_verify
import base64, os
#from hashlib import sha512
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS 
import Crypto.Hash.SHA512 as SHA512
#from hashlib import sha512 as SHA512

PUBKEY_FILE = os.path.dirname(__file__)+"/kioubit-auth-pubkey.pem"

class AuthVerifyer ():

    def __init__(self,domain, pubkey=PUBKEY_FILE):
        self.domain = domain
        with open(pubkey) as pk:
            pk_content = ""
            for line in pk.readlines():
                pk_content += line
            print(pk_content)
            self.pubkey = ECC.import_key(pk_content)
            #self.pubkey.set_pubkey(
            #    load_publickey(OpenSSL.crypto.FILETYPE_PEM, pk_content)
            #)
        
        print(self.pubkey)
        
    def verify(self, params, signature):
        # sig = base64.b64decode(signature)
        # print(type(sig))
        #OpenSSL_verify(self.pubkey, sig
        #, base64.b64decode(params), "sha512")
        h = SHA512.new()
        h.update(base64.b64decode(params))
        #print(h.hexdigest())
        verifier = DSS.new(self.pubkey, 'fips-186-3')
        valid = verifier.verify(h, signature)
        return valid

if __name__ == "__main__":
    example_com_verifier = AuthVerifyer("example.com")
    example_com_verifier.verify(
        params="eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI2NjkyNiwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=",
        signature="MIGIAkIBAmwz3sQ1vOkH8+8e0NJ8GsUqKSaazIWmYDp60sshlTo7gCAopZOZ6/+tD6s+oEGM1i5mKGbHgK9ROATQLHxUZecCQgCa2N828uNn76z1Yg63/c7veMVIiK4l1X9TCUepJnJ3mCto+7ogCP+2vQm6GHipSNRF4wnt6tZbir0HZvrqEnRAmA=="
        )
#params = "eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI1NjI5NSwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=", 
#signature = 'MIGHAkFy1m+9ahjIc5cJk/p+RiXJbhbWT5rPSJNg9Q3c8UTAM4F7lz2OqdWHw6GZN5NQgvqm6OB3Y751djYwCd54y2Kn4wJCAcBaOrtSclxkGIleVx183PhTnSr97r2F089PsDzNXIBvH5pYUwvJX7hG0op0f5tPm7fl12HOOrr8Q6kWW+XTrgGX'
