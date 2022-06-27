import os
from enum import Enum
from dotenv import load_dotenv
from json import load

with open('config.json','r') as f:
        load_dotenv(load(f)["env_path"])


class KEYS(Enum):
    SHODAN = os.environ.get("SHODAN")
    BINARYEDGE = os.environ.get("BINARYEDGE")
    SECURITYTRAILS = os.environ.get("SECURITYTRAILS")
    VIRUSTOTAL = os.environ.get("VIRUSTOTAL")

class STATUS(Enum):
    INVALID = "Invalid API Key !!!"
    NOKEY = "No API Key Found !!!"

class INFO(Enum):
    PUBLIC_API = ['google','bing','duckduckgo','urlscan','threatcrowd','rapiddns','alienvault']
    PRIVATE_API = ['shodan','binaryedge','securitytrails','virustotal']

class FILES(Enum):
    WRITESTATUS = "subdomain.csv"
    INIT_PROB = "probing.csv"
    TECHSTACK = "techstack.csv"
    HISTORIC = "historic.csv"
    PORTSCANING = "scaning.csv"
