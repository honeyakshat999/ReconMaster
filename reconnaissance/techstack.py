from Wappalyzer import Wappalyzer, WebPage
from requests.exceptions import ConnectionError,ReadTimeout,InvalidURL
from pandas import DataFrame,read_csv
from multiprocessing import Pool
from os.path import join
import warnings
from utils import helper
warnings.filterwarnings('ignore')


logger=helper.LOGGER

def init_techstack(filepath):
    try:
        urls=readstack(join(filepath,'probing.csv'))
        logger.info("Attempting to TechStack Probed Subdomains")
        if bool(urls):
            with Pool(4) as p:
                data=p.map(gettechstackdata,urls)
        else:
            data=[]
        logger.info("Successfully TechStacked Probed Subdomains")
        writetechstack(data,join(filepath,'techstack.csv'))
    except Exception as e:
        logger.error(f"Unable To TechStack Probed Subdomains Due to following Error : {e}")

def writetechstack(data,outfile):
    try:
        logger.info("Attempting So Save Techstack Data")
        DataFrame(data).dropna().to_csv(outfile,index=False)
        logger.info(f"Successfully Saved Techstack Data to {outfile}")
    except Exception as e:
        logger.error(f"Unable To Save Techstack Data to {outfile} Due to following Error : {e}")


def readstack(inpfile):
    try:
        logger.info("Attempting To Read Probing Data")
        data=read_csv(inpfile).query("status=='Live'")["urls"].tolist()
        logger.info("Successfully Readed Probing Data")
        return data
    except Exception as e:
        logger.error(f"Unable To Read Probing Data Due to following Error : {e}")
    


def gettechstackdata(url):
    try:
        simplifieddata={"url":url,"versions":[]}
        webpage = WebPage.new_from_url(f"http://{url}",timeout=2.50)
        wappalyzer = Wappalyzer.latest()
        data = wappalyzer.analyze_with_versions_and_categories(webpage)
        for x in data:
            if data[x]["versions"]:
                simplifieddata["versions"].append(x+" "+data[x]["versions"][0])
            else:
                simplifieddata["versions"].append(x)
        simplifieddata["versions"]=",".join(simplifieddata["versions"])
        return simplifieddata
    except (ConnectionError,ReadTimeout,InvalidURL) as ce:
        return {"url":None,"versions":None}
