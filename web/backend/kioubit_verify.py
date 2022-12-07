#! /usr/bin/env python3

import base64
import os
import json
import time
import logging
import OpenSSL
from OpenSSL.crypto import load_publickey, FILETYPE_PEM, verify, X509


PUBKEY_FILE = os.path.dirname(__file__)+"/kioubit-auth-pubkey.pem"


class AuthVerifyer ():

    def __init__(self, domain, pubkey=PUBKEY_FILE):
        self.domain = domain
        with open(pubkey) as pk:
            pk_content = ""
            for line in pk.readlines():
                pk_content += line
            logging.debug(pk_content)
        pkey = load_publickey(FILETYPE_PEM, pk_content)
        self.x509 = X509()
        self.x509.set_pubkey(pkey)

        logging.debug(self.x509)

    def verify(self, params, signature):
        # logging.debug(type(sig))
        # OpenSSL_verify(self.pubkey, sig
        # , base64.b64decode(params), "sha512")
        sig = base64.b64decode(signature)
        logging.info(f"sig: {sig}")
        logging.info(f"params: {params}")
        try:
            verify(self.x509, sig, params, 'sha512')
        except OpenSSL.crypto.Error:
            return False, "Signature Failed"

        try:
            user_data = json.loads(base64.b64decode(params))
            if (time.time() - user_data["time"]) > 60:
                return False, "Signature to old"
        except json.decoder.JSONDecodeError:
            # we shouldn't get here unless kioubit's service is misbehaving
            return False, "invalid JSON"
        except KeyError:
            return False, "value not found in JSON"
        logging.debug(user_data)
        return True, user_data


if __name__ == "__main__":
    example_com_verifier = AuthVerifyer("example.com")
    logging.info(example_com_verifier.verify(
        params=b"eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI2NjkyNiwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=",
        signature=b"MIGIAkIBAmwz3sQ1vOkH8+8e0NJ8GsUqKSaazIWmYDp60sshlTo7gCAopZOZ6/+tD6s+oEGM1i5mKGbHgK9ROATQLHxUZecCQgCa2N828uNn76z1Yg63/c7veMVIiK4l1X9TCUepJnJ3mCto+7ogCP+2vQm6GHipSNRF4wnt6tZbir0HZvrqEnRAmA=="
    ))
#params = "eyJhc24iOiI0MjQyNDIzMDM1IiwidGltZSI6MTY2ODI1NjI5NSwiYWxsb3dlZDQiOiIxNzIuMjIuMTI1LjEyOFwvMjYsMTcyLjIwLjAuODFcLzMyIiwiYWxsb3dlZDYiOiJmZDYzOjVkNDA6NDdlNTo6XC80OCxmZDQyOmQ0MjpkNDI6ODE6OlwvNjQiLCJtbnQiOiJMQVJFLU1OVCIsImF1dGh0eXBlIjoibG9naW5jb2RlIiwiZG9tYWluIjoic3ZjLmJ1cmJsZS5kbjQyIn0=",
#signature = 'MIGHAkFy1m+9ahjIc5cJk/p+RiXJbhbWT5rPSJNg9Q3c8UTAM4F7lz2OqdWHw6GZN5NQgvqm6OB3Y751djYwCd54y2Kn4wJCAcBaOrtSclxkGIleVx183PhTnSr97r2F089PsDzNXIBvH5pYUwvJX7hG0op0f5tPm7fl12HOOrr8Q6kWW+XTrgGX'
