import requests
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
from pandas import DataFrame
from os.path import join


maxprocessors=4

def readata(inputfile):
    with open(inputfile,'r+') as file:
        data=[x.split(',')[0] for x in file.read().splitlines()[1:]]
        data=DataFrame(data,columns=["urls"])
    return data

def active_urls(url):
    try:
        if requests.get(f"http://{url}",verify=False,timeout=2.50).status_code<400:
            return url
    except:
        return

def writedata(data,urls,outputfile):
    data["status"]=data["urls"].isin(urls).map({True:"Live",False:"Dead"})
    data.sort_values(by=["status"],ascending=False).to_csv(outputfile,index=False)

def init_prob(filepath):
    inputfile,outputfile=join(filepath,'subdomain.csv'),join(filepath,'probing.csv')
    data=readata(inputfile)
    with Pool(maxprocessors) as p:
        checked_urls=p.map(active_urls,data["urls"].tolist())
    writedata(data,checked_urls,outputfile)
    print("\nThe data has been saved to probing.csv")
