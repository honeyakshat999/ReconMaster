from json import load
import logging
import os
from . import consts
import requests



LOGO="""
   __                                          _            
  /__\ ___  ___ ___  _ __  _ __ ___   __ _ ___| |_ ___ _ __ 
 / \/// _ \/ __/ _ \| '_ \| '_ ` _ \ / _` / __| __/ _ \ '__|
/ _  \  __/ (_| (_) | | | | | | | | | (_| \__ \ ||  __/ |   
\/ \_/\___|\___\___/|_| |_|_| |_| |_|\__,_|___/\__\___|_|   
    \n\n"""


def get_config(value):
    with open('config.json','r') as f:
        result=load(f)[value]
    return result

def get_logger(name,level):
    logpath=get_config("log_path")
    if not os.path.exists(logpath):
        os.mkdir(logpath)
    logging.basicConfig(filename=os.path.join(logpath,f'{get_config("log_file_name")}.log'),format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',filemode="w",encoding='utf-8',level=level,datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    ch.setLevel(level)
    logger.addHandler(ch)
    return logger


def get_error_keys():
    apierrors={}
    for key in consts.KEYS:
        if not bool(key.value):
            apierrors[key.name.lower()]=consts.STATUS.NOKEY.value
        else:
            if key.name=="SHODAN":
                if requests.get(f"https://api.shodan.io/shodan/host/8.8.8.8?key={key.value}").status_code!=200:
                    apierrors[key.name.lower()]=consts.STATUS.INVALID.value
            elif key.name=='BINARYEDGE':
                if requests.get('https://api.binaryedge.io/v2/user/subscription',headers={'X-Key':f"{key.value}"}).status_code!=200:
                    apierrors[key.name.lower()]=consts.STATUS.INVALID.value
            elif key.name=='VIRUSTOTAL':
                if requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={key.value}").status_code!=200:
                    apierrors[key.name.lower()]=consts.STATUS.INVALID.value
            elif key.name=='SECURITYTRAILS':
                if requests.get("https://api.securitytrails.com/v1/history/trello.com/dns/a",headers={'Content-Type':"application/json",'apikey':f"{key.value}"}).status_code!=200:
                    apierrors[key.name.lower()]=consts.STATUS.INVALID.value
    return apierrors


def displaystatus(apierrors):
    print(LOGO+"Engines\t\t\tStatus\t\tReason\n")
    for x in consts.INFO.PUBLIC_API.value+consts.INFO.PRIVATE_API.value:
        if x in apierrors:
            print(f"{x:<15}\t\tInactive\t{apierrors[x]}")
        else:
            print(f"{x:<15}\t\tActive")
    print("\n\n")



LOGGER=get_logger("ReconMaster",logging.INFO)