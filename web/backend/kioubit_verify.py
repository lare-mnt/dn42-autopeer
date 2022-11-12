#! /usr/bin/env python3

import base64, os
from OpenSSL.crypto import load_publickey, FILETYPE_PEM, verify, X509
import OpenSSL


PUBKEY_FILE = os.path.dirname(__file__)+"/kioubit-auth-pubkey.pem"

class AuthVerifyer ():

    def __init__(self,domain, pubkey=PUBKEY_FILE):
        self.domain = domain
        with open(pubkey) as pk:
            pk_content = ""
            for line in pk.readlines():
                pk_content += line
            print(pk_content)
        pkey = load_publickey(FILETYPE_PEM, pk_content)
        self.x509 = X509()
        self.x509.set_pubkey(pkey)
        
        print(self.x509)
        
    def verify(self, params, signature):
        # print(type(sig))
        #OpenSSL_verify(self.pubkey, sig
        #, base64.b64decode(params), "sha512")
        sig = base64.b64decode(signature)
        print(f"sig: {sig}")
        print(f"params: {params}")
        try:
            verify(self.x509, sig, params, 'sha512')
        except OpenSSL.crypto.Error:
            return False, "Signature Failed"
        #h = SHA512.new()
        #h.update(base64.b64decode(params))
        #print(h.hexdigest())
        #verifier = DSS.new(self.pubkey, 'deterministic-rfc6979')
        #valid = verifier.verify(h, base64.b64decode(signature))
        return True, ""

if __name__ == "__main__":
    example_com_verifier = AuthVerifyer("example.com")
    print (example_com_verifier.verify(
        params=b"eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI2NjkyNiwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=",
        signature=b"MIGIAkIBAmwz3sQ1vOkH8+8e0NJ8GsUqKSaazIWmYDp60sshlTo7gCAopZOZ6/+tD6s+oEGM1i5mKGbHgK9ROATQLHxUZecCQgCa2N828uNn76z1Yg63/c7veMVIiK4l1X9TCUepJnJ3mCto+7ogCP+2vQm6GHipSNRF4wnt6tZbir0HZvrqEnRAmA=="
        ) )
#params = "eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI1NjI5NSwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=", 
#signature = 'MIGHAkFy1m+9ahjIc5cJk/p+RiXJbhbWT5rPSJNg9Q3c8UTAM4F7lz2OqdWHw6GZN5NQgvqm6OB3Y751djYwCd54y2Kn4wJCAcBaOrtSclxkGIleVx183PhTnSr97r2F089PsDzNXIBvH5pYUwvJX7hG0op0f5tPm7fl12HOOrr8Q6kWW+XTrgGX'
