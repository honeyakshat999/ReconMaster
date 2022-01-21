import argparse
import requests
import re
import os
from shodan import Shodan
import json
from pybinaryedge import BinaryEdge
import threading
import multiprocessing

ar = argparse.ArgumentParser(description='List the Required arguments')

ar.add_argument("-U","--url", required=True,help="Enter Domain name without https or http.(ex- example.com)",type=str)
ar.add_argument("-F","--file", required=True,help="where to save results",type=str)
ar.add_argument("-E","--engine", required=False,help="where to collect data. use 'all' keyword to use every search engine",type=str,default='all')
ar.add_argument("-S","--search", required=False,help="To run a Search Engine scan",type=str)

args = ar.parse_args()

pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + args.url.lstrip('.').split()[0] + ")"
f = open(args.file, mode='a+', encoding='utf-8')

def google():
    for i in range(0,110,10):
        url = "https://www.google.com/search?q=site%3a"+args.url+"&start="+str(i)
        data = requests.get(url).text
        matching = set(re.compile(pattern).findall(data))
        for i in matching:
            f.write(''.join(i)+'\n')

def bing():
    for i in range(0, 50, 5):
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        url = "https://www.bing.com/search?q=site%3A."+args.url+"&first="+str(i)
        data = requests.get(url,headers=header).text
        matching = set(re.compile(pattern).findall(data))
        for j in matching:
            f.write(''.join(j) + '\n')

def duckduckgo():
    for i in range(-20,530,50):
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        url =  "https://duckduckgo.com/html/?q=site:"+args.url+"&s="+str(i)
        data = requests.get(url,headers=header).text
        matching = set(re.compile(pattern).findall(data))
        for j in matching:
            f.write(''.join(j) + '\n')


def shodandata():
    api = Shodan(getkey('shodan_key'))
    data = api.search(args.url)
    match = re.compile(pattern).findall(json.dumps(data))
    for i in match:
        f.write(i[1]+"\n")


def alienvault():
    url = "https://otx.alienvault.com/api/v1/indicators/domain/"+ args.url +"/passive_dns"
    a = requests.get(url).text
    result_json=json.loads(a)
    hostname = args.url
    for i in range(0,100):
        try:
            hostname = result_json['passive_dns'][i]['hostname']
            f.write(''.join(hostname)+'\n')

        except IndexError:
            return

def bina():
    be = BinaryEdge(getkey('binaryedge_key'))
    search = args.url
    results = be.domain_subdomains(search)
    for ip in results['events']:
        f.write(''.join(ip) + '\n')


def rapiddns():
    searchurl = args.url
    url = "https://rapiddns.io/s/"+searchurl
    data = requests.get(url).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        f.write(''.join(i) + '\n')

def securitytrails():

    def get_sub_domains(domain):
        url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"
        querystring = {"children_only":"true"}
        headers = {
        'accept': "application/json",
        'apikey': getkey('securitytrails_key')
        }
        response = requests.request("GET", url, headers=headers, params=querystring)
        result_json=json.loads(response.text)
        sub_domains=[i+'.'+domain for i in result_json['subdomains']]
        for i in sub_domains:
            f.write(i+'\n')
        return sub_domains

    get_sub_domains(args.url)

def threatcrowd():
    domain = args.url
    data = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+domain).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        f.write(''.join(i) + '\n')

def urlscan():
    url = args.url
    data = requests.get("https://urlscan.io/api/v1/search/?q=domain:" + url).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        f.write(''.join(i) + '\n')

def virustotal():
    apikey = getkey('virustotal_key')
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    domain = args.url
    params = {'apikey':apikey,'domain':domain}
    data = requests.get(url, params=params).text
    matching = set(re.compile(pattern).findall(data))
    for i in matching:
        f.write(''.join(i) + '\n')

def removeDups(filename):
        with open(filename, 'r+') as file:
            lines=file.readlines()
            file.seek(0)
            file.truncate()
            for line in set(lines):
                file.write(line)
        

def getkey(keyname):
    _loc="key.txt"
    with open(_loc,'r') as file:
        data={k.strip():v.strip() for k,v in [x.split(':') for x in file.read().splitlines()]}
    return data.get(keyname)


if(args.search in ["true","True"]):
    google()
    bing()
    duckduckgo()
    shodandata()
    f.close()
    removeDups(args.file)
    
elif(args.engine == 'all'):
    google()
    bing()
    duckduckgo()
    shodandata()
    alienvault()
    bina()
    rapiddns()
    securitytrails()
    threatcrowd()
    urlscan()
    virustotal()
    f.close()
    removeDups(args.file)

elif args.engine in ['alienvault','virustotal','urlscan','threatcrowd','securitytrails','rapiddns','binaryedge']:
    exec(f"{args.engine}()")
    f.close()
    removeDups(args.file)
    
else:
    print("wrong parameter values")
