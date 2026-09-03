# Additional Python security regression corpus.

import logging
import os
import requests
import tarfile
import tempfile


# EXPECT PY.SEC.013
def fetch_remote(request):
    target = request.args["url"]
    return requests.get(target)


# EXPECT PY.SEC.014
logger = logging.getLogger(__name__)
api_token = os.environ.get("API_TOKEN")
logger.info("token=%s", api_token)


# EXPECT PY.SEC.015
tmp = tempfile.mktemp()


# EXPECT PY.SEC.016
os.chmod("shared.txt", 0o777)


# EXPECT PY.SEC.017
tar = tarfile.open("archive.tar")
tar.extractall("/tmp/app")
