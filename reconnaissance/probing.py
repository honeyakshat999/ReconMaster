import requests
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
from pandas import DataFrame
from os.path import join
from utils import utilities


logger=utilities.Helper.LOGGER

def readata(inputfile):
    try:
        logger.info("Attempting To Read Subdomain Data")
        with open(inputfile,'r+') as file:
            data=[x.split(',')[0] for x in file.read().splitlines()[1:]]
            data=DataFrame(data,columns=["urls"])
        logger.info("Successfully Readed Subdomain Data")
        return data
    except Exception as e:
        logger.error(f"Unable To Read Subdomain Data Due to following Error : {e}")


def active_urls(url,timeout):
    try:
        if requests.get(f"http://{url}",verify=False,timeout=timeout).status_code<400:
            return url
    except:
        return

def writedata(data,urls,outputfile):
    try:
        logger.info("Attempting So Save Probed Data")
        data["status"]=data["urls"].isin(urls).map({True:"Live",False:"Dead"})
        data.sort_values(by=["status"],ascending=False).to_csv(outputfile,index=False)
        logger.info(f"Successfully Saved Probed Data to {outputfile}")
    except Exception as e:
        logger.error(f"Unable To Save Probed Data to {outputfile} Due to following Error : {e}")

def init_prob(filepath):
    try:
        logger.info("Attempting to Probe Subdomains")
        inputfile,outputfile=join(filepath,'subdomain.csv'),join(filepath,'probing.csv')
        data=readata(inputfile)
        urls=data["urls"].tolist()
        timeout=utilities.Config.get_prop("request_timeout")
        with Pool(utilities.Config.get_prop('max_processors')) as p:
            checked_urls=p.starmap(active_urls,tuple(zip(urls,[timeout]*len(urls))))
        logger.info("Successfully Probed Subdomains")
        writedata(data,checked_urls,outputfile)

    except Exception as e:
        logger.error(f"Unable To Probed Subdomains Due to following Error : {e}")
