from Wappalyzer import Wappalyzer, WebPage
from requests.exceptions import ConnectionError,ReadTimeout,InvalidURL
from pandas import DataFrame,read_csv
from multiprocessing import Pool
from os.path import join
import warnings
warnings.filterwarnings('ignore')

def techstack(filepath):
    urls=readstack(join(filepath,'probing.csv'))
    with Pool(4) as p:
        data=p.map(gettechstackdata,urls)
    writetechstack(data,join(filepath,'techstack.csv'))
    print("\nThe data has been saved to techstack.csv")
    

def writetechstack(data,outfile):
    DataFrame(data).to_csv(outfile,index=False)


def readstack(inpfile):
    return read_csv(inpfile).query("status=='Live'")["urls"].tolist()


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
        return
