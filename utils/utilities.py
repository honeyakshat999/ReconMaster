import logging
from datetime import datetime
import os
from utils import consts
import json
import requests
from werkzeug.serving import make_server
from threading import Thread

class Logger:
    
    def __init__(self,name,level="info"):
        self.name=name
        self.level=level
        self.level=self._map_level()
        self.format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s'
        self.formatter=logging.Formatter(self.format,datefmt='%Y-%m-%d %H:%M:%S')
        self.logger=logging.getLogger(self.name)
        #self.logger.setLevel(self.level)

    def _map_level(self):
        levels={
        "info":logging.INFO,
        "debug":logging.DEBUG,
        "warning":logging.WARNING,
        "error":logging.ERROR,
        "critical":logging.CRITICAL
                }
        return levels[self.level.lower()]


    @classmethod
    def Logger(cls,name,addHandlers,level="info"):
        logger=cls(name,level)
        if isinstance(addHandlers,(list,tuple)):
            if bool(addHandlers[0]):
                if not any([isinstance(handler,logging.StreamHandler) for handler in logger.logger.handlers]):
                    logger.add_stream_handler()
            if bool(addHandlers[-1]):
                if not any([isinstance(handler,logging.FileHandler) for handler in logger.logger.handlers]):
                        logger.add_file_handler()
        else:
            if not any([handler for handler in logger.logger.handlers if isinstance(handler,logging.FileHandler) or isinstance(handler,logging.StreamHandler)]):
                logger.add_stream_handler()
                logger.add_file_handler()
        return logger.logger

    def add_stream_handler(self):
        sh=logging.StreamHandler()
        sh.setFormatter(self.formatter)
        sh.setLevel(self.level)
        self.logger.addHandler(sh)

    def add_file_handler(self):
        logpath=Config.get_prop("log_path")
        if not os.path.exists(os.path.join(os.getcwd(),logpath)):
            os.makedirs(logpath)
        logfile=f"{datetime.strftime(datetime.now(),'%Y-%h-%d %H%M%S')}.log"
        fh = logging.FileHandler(filename=os.path.join(logpath,logfile),mode="w",encoding='utf-8',delay=True)
        fh.setFormatter(self.formatter)
        fh.setLevel(self.level)
        self.logger.addHandler(fh)
    
    def shutdown(self):
        self.logger.shutdown()

class Server:

    def __init__(self,app,host,port,threaded=False,processes=1):
        self.server = make_server(host, port, app, threaded, processes)
        self.logger=Helper.LOGGER
        self.threads=[]

    def run(self):
        runthread=Thread(target=self.server.serve_forever,name="ServerThreadRun")
        self.threads.append(runthread)
        runthread.start()
        self.logger.info(f"Server Started on {self.server.host}:{self.server.port}")

    def shutdown(self):
        stopthread=Thread(target=self.server.shutdown,name="ServerThreadShut")
        self.threads.append(stopthread)
        stopthread.start()
        self.logger.info(f"Server Stoped")


class Config:

    def __init__(self):
        path=os.path.join(os.getcwd(),consts.PATH.CONFIG_PATH.value)
        if os.path.exists(path):
            with open(path,"r") as config:
                self.config=json.loads(config.read())
        else:
            raise FileNotFoundError(f"Can't Able to find file as per .env file {consts.PATH.CONFIG_PATH.value}")

    @classmethod
    def get_prop(cls,propname):
        try:
            if cls.config:
                return cls.config[propname]
        except AttributeError:
            config=cls()
            return config.config[propname]

    @classmethod
    def get_props(cls,propnames):
        try:
            if cls.config:
                return [cls.config[propname] for propname in propnames]
        except AttributeError:
            config=cls()
            return [config.config[propname] for propname in propnames]

class Helper:

    LOGGER=Logger.Logger("Reconmaster",Config.get_props(["show_logs","write_logs"]))
    LOGO="""
      __                                          _            
     /__\ ___  ___ ___  _ __  _ __ ___   __ _ ___| |_ ___ _ __ 
    / \/// _ \/ __/ _ \| '_ \| '_ ` _ \ / _` / __| __/ _ \ '__|
    / _  \  __/ (_| (_) | | | | | | | | | (_| \__ \ ||  __/ |   
    \/ \_/\___|\___\___/|_| |_|_| |_| |_|\__,_|___/\__\___|_|   
        \n\n"""

    @staticmethod
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


    @staticmethod
    def displaystatus(apierrors):
        print(Helper.LOGO+"Engines\t\t\tStatus\t\tReason\n")
        for x in consts.INFO.PUBLIC_API.value+consts.INFO.PRIVATE_API.value:
            if x in apierrors:
                print(f"{x:<15}\t\tInactive\t{apierrors[x]}")
            else:
                print(f"{x:<15}\t\tActive")
        print("\n\n")

