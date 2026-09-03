# EXPECT PY.SEC.009

import requests

def fetch(url):
    verify = False
    return requests.get(url, verify=verify)
