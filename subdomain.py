import requests
import re
from shodan import Shodan
import json
from pybinaryedge import BinaryEdge
from pandas import DataFrame
from os.path import join


output={"urls":[],"engine":[]}

def google(url,pattern):
    for i in range(0,110,10):
        url = "https://www.google.com/search?q=site%3a"+url+"&start="+str(i)
        data = requests.get(url).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            output["urls"].append(''.join(i))
            output["engine"].append("google")

def bing(url,pattern):
    for i in range(0, 50, 5):
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        url = "https://www.bing.com/search?q=site%3A."+url+"&first="+str(i)
        data = requests.get(url,headers=header).text
        matching = set(re.compile(pattern).findall(data))
        for j in matching:
            output["urls"].append(''.join(j))
            output["engine"].append("bing")

def duckduckgo(url,pattern):
    for i in range(-20,530,50):
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        url =  "https://duckduckgo.com/html/?q=site:"+url+"&s="+str(i)
        data = requests.get(url,headers=header).text
        matching = set(re.compile(pattern).findall(data))
        for j in matching:
            output["urls"].append(''.join(j))
            output["engine"].append("duckduckgo")


def shodan(url,shodan_key,pattern):
    api = Shodan(shodan_key)
    data = api.search(url)
    match = re.compile(pattern).findall(json.dumps(data))
    for i in match:
        output["urls"].append(i[1])
        output["engine"].append("shodan")
    

def alienvault(url):
    url = "https://otx.alienvault.com/api/v1/indicators/domain/"+ url +"/passive_dns"
    result_json = requests.get(url).json()
    hostname = url
    for i in range(0,100):
        try:
            hostname = result_json['passive_dns'][i]['hostname']
            output["urls"].append(''.join(hostname))
            output["engine"].append("alienvault")

        except IndexError:
            return

def binaryedge(url,binaryedge_key):
    be = BinaryEdge(binaryedge_key)
    search = url
    results = be.domain_subdomains(search)
    for ip in results['events']:
        output["urls"].append(''.join(ip))
        output["engine"].append("binaryedge")


def rapiddns(url,pattern):
    searchurl = url
    url = "https://rapiddns.io/s/"+searchurl
    data = requests.get(url).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        output["urls"].append(''.join(i))
        output["engine"].append("rapiddns")


def securitytrails(url,securitytrails_key):

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

    get_sub_domains(url,securitytrails_key)

def threatcrowd(url,pattern):
    domain = url
    data = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+domain).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        output["urls"].append(''.join(i))
        output["engine"].append("threatcrowd")

def urlscan(url,pattern):
    url = url
    data = requests.get("https://urlscan.io/api/v1/search/?q=domain:" + url).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        output["urls"].append(''.join(i))
        output["engine"].append("urlscan")

def virustotal(url,virustotal_key,pattern):
    apikey = virustotal_key
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    domain = url
    params = {'apikey':apikey,'domain':domain}
    data = requests.get(url, params=params).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        output["urls"].append(''.join(i))
        output["engine"].append("virustotal")
        
     
def writestatus(url,engine,filepath,apierrors,keydict):
    pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + url + ")"
    if(engine == 'all'):
        google(url,pattern)
        bing(url,pattern)
        duckduckgo(url,pattern)
        alienvault(url)
        rapiddns(url,pattern)
        threatcrowd(url,pattern)
        urlscan(url,pattern)
        for y in [x for x in ['shodan','binaryedge','virustotal','securitytrails'] if x not in apierrors]:
            if y=='shodan':
                shodan(url,keydict[f'{y}_key'],pattern)
            elif y=='binaryedge':
                binaryedge(url,keydict[f'{y}_key'])
            elif y=='virustotal':
                virustotal(url,keydict[f'{y}_key'],pattern)
            else:
                securitytrails(url,keydict[f'{y}_key'])
        df=DataFrame(output)
        df=df.groupby("urls",as_index=False)['engine'].agg(lambda x:",".join(set(x)))
        df.to_csv(join(filepath,'subdomain.csv'),index=False)
        print('\nThe data has been saved to subdomain.csv')

    elif engine in ['google','bing','duckduckgo','shodan','alienvault','virustotal','urlscan','threatcrowd','securitytrails','rapiddns','binaryedge']:
        if engine in apierrors:
            print(f"\ncan't use {engine} because of the following problem: {apierrors[engine]}")
        else:
            if engine  in ['google','bing','duckduckgo','urlscan','threatcrowd','rapiddns','alienvault']:
                exec(f"{engine}({url,pattern})")
            else:
                if y=='shodan':
                    shodan(url,keydict[f'{y}_key'],pattern)
                elif y=='binaryedge':
                    binaryedge(url,keydict[f'{y}_key'])
                elif y=='virustotal':
                    virustotal(url,keydict[f'{y}_key'],pattern)
                else:
                    securitytrails(url,keydict[f'{y}_key'])

            df=DataFrame(output)
            df.to_csv(join(filepath,'subdomain.csv'),index=False)
            print('\nThe data has been saved to subdomain.csv')

    else:
        print("\nwrong parameter values!!!")
        
        
if __name__=="__main__":            
    writestatus()
