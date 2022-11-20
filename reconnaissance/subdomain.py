import requests
import re
from shodan import Shodan
import json
from pybinaryedge import BinaryEdge
from pandas import DataFrame
from os.path import join
from utils import consts
from utils.utilities import Helper


output={"urls":[],"engine":[]}
logger=Helper.LOGGER

def google(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Google")
        for i in range(0,110,10):
            url = "https://www.google.com/search?q=site%3a"+url+"&start="+str(i)
            data = requests.get(url).text
            matching = set(re.compile(pattern).findall(data))
            for i in matching:
                output["urls"].append(''.join(i))
                output["engine"].append("google")
        logger.info("Fetching Data From Google Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Google Due To The Following Error : {e}")

def bing(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Bing")
        for i in range(0, 50, 5):
            header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
            url = "https://www.bing.com/search?q=site%3A."+url+"&first="+str(i)
            data = requests.get(url,headers=header).text
            matching = set(re.compile(pattern).findall(data))
            for j in matching:
                output["urls"].append(''.join(j))
                output["engine"].append("bing")
        logger.info("Fetching Data From Bing Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Bing Due To The Following Error : {e}")


def duckduckgo(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From DuckduckGo")
        for i in range(-20,530,50):
            header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
            url =  "https://duckduckgo.com/html/?q=site:"+url+"&s="+str(i)
            data = requests.get(url,headers=header).text
            matching = set(re.compile(pattern).findall(data))
            for j in matching:
                output["urls"].append(''.join(j))
                output["engine"].append("duckduckgo")
        logger.info("Fetching Data From DuckDuckGo Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From DuckDuckGo Due To The Following Error : {e}")

def shodan(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Shodan")
        api = Shodan(consts.KEYS.SHODAN.value)
        data = api.search(url)
        match = re.compile(pattern).findall(json.dumps(data))
        for i in match:
            output["urls"].append(i[1])
            output["engine"].append("shodan")
        logger.info("Fetching Data From Shodan Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Shodan Due To The Following Error : {e}")
    

def alienvault(url,*args):
    url = "https://otx.alienvault.com/api/v1/indicators/domain/"+ url +"/passive_dns"
    result_json = requests.get(url).json()
    hostname = url
    try:
        logger.info("Attempting To Fetch Data From Alienvault")
        if 'passive_dns' in result_json:
            for i in range(result_json["count"]):
                hostname = result_json['passive_dns'][i]['hostname']
                output["urls"].append(''.join(hostname))
                output["engine"].append("alienvault")
        else:
            raise Exception(result_json)
        logger.info("Fetching Data From Alienvault Completed")

    except Exception as e:
        logger.error(f"Unable To Fetch Data From Alienvault Due To The Following Error : {e}")

def binaryedge(url,*args):
    try:
        logger.info("Attempting To Fetch Data From Binaryedge")
        be = BinaryEdge(consts.KEYS.BINARYEDGE.value)
        search = url
        results = be.domain_subdomains(search)
        for ip in results['events']:
            output["urls"].append(''.join(ip))
            output["engine"].append("binaryedge")
        logger.info("Fetching Data From Binaryedge Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Binaryedge Due To The Following Error : {e}")

def rapiddns(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Rapiddns")
        searchurl = url
        url = "https://rapiddns.io/s/"+searchurl
        data = requests.get(url).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            output["urls"].append(''.join(i))
            output["engine"].append("rapiddns")
        logger.info("Fetching Data From Rapiddns Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Rapiddns Due To The Following Error : {e}")


def securitytrails(url,*args):

    def get_sub_domains(domain,securitytrails_key):
        url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"
        querystring = {"children_only":"true"}
        headers = {
        'accept': "application/json",
        'apikey': securitytrails_key
        }
        response = requests.request("GET", url, headers=headers, params=querystring)
        result_json=json.loads(response.text)
        sub_domains=[i+'.'+domain for i in result_json['subdomains']]
        for i in sub_domains:
            output["urls"].append(i)
            output["engine"].append("securitytrails")
        return sub_domains

    try:
        logger.info("Attempting To Fetch Data From Securitytrails")
        get_sub_domains(url,consts.KEYS.SECURITYTRAILS.value)
        logger.info("Fetching Data From Securitytrails Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Securitytrails Due To The Following Error : {e}")


def threatcrowd(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Threatcrowd")
        domain = url
        data = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+domain).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            output["urls"].append(''.join(i))
            output["engine"].append("threatcrowd")
        logger.info("Fetching Data From Threatcrowd Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Threatcrowd Due To The Following Error : {e}")

def urlscan(url,pattern):
    try:
        logger.info("Attempting To Fetch Data From Urlscan")
        url = url
        data = requests.get("https://urlscan.io/api/v1/search/?q=domain:" + url).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            output["urls"].append(''.join(i))
            output["engine"].append("urlscan")
        logger.info("Fetching Data From Urlscan Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Urlscan Due To The Following Error : {e}")


def virustotal(url,pattern):
    logger.info("Attempting To Fetch Data From Virustotal")
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    domain = url
    try:
        params = {'apikey':consts.KEYS.VIRUSTOTAL.value,'domain':domain}
        data = requests.get(url, params=params).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            output["urls"].append(''.join(i))
            output["engine"].append("virustotal")
        logger.info("Fetching Data From VirusTotal Completed")
    except Exception as e:
        logger.error(f"Unable To Fetch Data From Virustotal Due To The Following Error : {e}")
        
     
def init_subdomain(url,engine,filepath,apierrors):
    pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + url + ")"
    if(engine == 'all'):
        for engine in consts.INFO.PUBLIC_API.value+consts.INFO.PRIVATE_API.value:
                if engine not in apierrors:
                    exec(f"{engine}('{url}','{pattern}')")
        logger.info("Attempting To Saving Fetched Data")
        df=DataFrame(output)
        df=df.loc[~df["urls"].str.startswith('.')]
        df=df.groupby("urls",as_index=False)['engine'].agg(lambda x:",".join(set(x)))
        df.to_csv(join(filepath,'subdomain.csv'),index=False)
        logger.info("The data has been saved to subdomain.csv")

    elif engine in consts.INFO.PUBLIC_API.value+consts.INFO.PRIVATE_API.value:
        if engine in apierrors:
            print(f"\ncan't use {engine} because of the following problem: {apierrors[engine]}")
        else:
            exec(f"{engine}('{url}','{pattern}')")
            logger.info("Attempting To Saving Fetched Data")
            df=DataFrame(output)
            df=df.loc[~df["urls"].str.startswith('.')]
            df.to_csv(join(filepath,'subdomain.csv'),index=False)
            logger.info("The data has been saved to subdomain.csv")

    else:
        logger.error("wrong parameter values!!!")
        
        
if __name__=="__main__":            
    init_subdomain()
