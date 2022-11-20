from .subdomain import init_subdomain
from .probing import init_prob
from .techstack import init_techstack
from .historic import init_historic
from .portscaning import init_portscaning
import os
from utils import consts,utilities


logger=utilities.Helper.LOGGER


def init_recon(url,engine,filepath):
    def run_recon(name,url,engine,filepath,apierrors):
        if name=="WRITESTATUS":
            init_subdomain(url,engine,filepath,apierrors)
        elif name=="INIT_PROB":
            init_prob(filepath)
        elif name=="TECHSTACK":
            init_techstack(filepath)
        elif name=="HISTORIC":
            init_historic(url,filepath)
        else:
            init_portscaning(url,filepath,utilities.Config.get_prop("request_timeout"))
        
    map_dict={"WRITESTATUS":"subdomain module","INIT_PROB":"probing module","TECHSTACK":"techstack module",
              "HISTORIC":"historic(web archieve) module","PORTSCANING":"port scaning module"}
    apierrors=utilities.Helper.get_error_keys()
    utilities.Helper.displaystatus(apierrors)
    if os.path.exists(filepath):
        logger.info(f"The data of {url} exists locally")
        logger.info("Checking For Missing File")
        available=os.listdir(filepath)
        for item in consts.FILES:
            if item.value not in available:
                logger.info(f"Missing File Founded : {item.value}")
                logger.info(f"Attempting to run : {map_dict[item.name]}")
                run_recon(item.name,url,engine,filepath,apierrors)
                logger.info(f"Successfully Runned : {map_dict[item.name]}")
        logger.info("No Missing File Found")

    else:
        os.makedirs(filepath)
        init_subdomain(url,engine,filepath,apierrors)
        logger.info("\n-----------------------------------------------------------------------\n")
        init_prob(filepath)
        logger.info("\n-----------------------------------------------------------------------\n")
        init_techstack(filepath)
        logger.info("\n-----------------------------------------------------------------------\n")
        init_historic(url,filepath)
        logger.info("\n-----------------------------------------------------------------------\n")
        init_portscaning(url,filepath,3)
