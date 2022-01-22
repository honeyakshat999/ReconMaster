import argparse
import requests
import re
from shodan import Shodan
import json
from pybinaryedge import BinaryEdge

ar = argparse.ArgumentParser(description='List the Required arguments',formatter_class=argparse.RawTextHelpFormatter)

ar.add_argument("-U","--url", required=True,help="\nEnter Domain name without https or http.(ex- example.com)",type=str)
ar.add_argument("-F","--file", required=True,help="\nWhere to save results (ex- filename or filepath)",type=str)
ar.add_argument("-E","--engine", required=False,help="""\nWhere to collect data. 
use 'all'(default) keyword to use every search engine.\n
other explicit options:                  
google
bing
duckduckgo
shodan          (api key required)
alienvault
virustotal      (api key required) 
urlscan 
threatcrowd 
securitytrails  (api key required)
rapiddns
binaryedge      (api key required)"""
                ,type=str,default='all')


args = ar.parse_args()

pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + args.url.lstrip('.').split()[0] + ")"
f = open(args.file, mode='a+', encoding='utf-8')
apierrors=[]
emptyapikeys=[]
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


def shodan():
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

def binaryedge():
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
    if keyname=='all':
        return data
    return data.get(keyname)

def checkkeys():
    keys=getkey('all')
    global emptyapikeys,apierrors
    for x in keys:
        y=x.split('_')[0]
        if keys[x] is None or keys[x]=='':
            emptyapikeys.append(y)
        else:
            if y=='shodan':
                if requests.get(f"https://api.shodan.io/shodan/host/8.8.8.8?key={keys[x]}").status_code!=200:
                    apierrors.append(y)
            elif y=='binaryedge':
                if requests.get('https://api.binaryedge.io/v2/user/subscription',headers={'X-Key':f"{keys[x]}"}).status_code!=200:
                    apierrors.append(y)
            elif y=='virustotal':
                if requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={keys[x]}").status_code!=200:
                    apierrors.append(y)
            elif y=='securitytrails':
                if requests.get("https://api.securitytrails.com/v1/history/trello.com/dns/a",headers={'Content-Type':"application/json",'apikey':f"{keys[x]}"}).status_code!=200:
                    apierrors.append(y)

      
        
def displaystatus():
    checkkeys()
    global emptyapikeys,apierrors
    print("Engines\t\t\tStatus\t\tReason\n")
    for x in ['google','bing','duckduckgo','alienvault','urlscan','threatcrowd','rapiddns']:
        print(f"{x:<15}\t\tActive")
    for x in ['shodan','virustotal','securitytrails','binaryedge']:
        if x in emptyapikeys:
            print(f"{x:<15}\t\tInnactive\tNo API Keys Found!!")
        elif x in apierrors:
            print(f"{x:<15}\t\tInnactive\tInvalid API Keys!!")
        else:
            print(f"{x:<15}\t\tActive")
    

displaystatus()
if(args.engine == 'all'):
    google()
    bing()
    duckduckgo()
    alienvault()
    rapiddns()
    securitytrails()
    threatcrowd()
    urlscan()
    for y in [x for x in ['shodan','binaryedge','virustotal','securitytrails'] if x not in apierrors+emptyapikeys]:
        exec(f'{y}()')
    f.close()
    removeDups(args.file)

elif args.engine in ['google','bing','duckduckgo','shodan','alienvault','virustotal','urlscan','threatcrowd','securitytrails','rapiddns','binaryedge']:
    if args.engine in apierrors+emptyapikeys:
        f.close()
        print(f"\ncan't use {args.engine}")
    else:
        exec(f"{args.engine}()")
        f.close()
        removeDups(args.file)

else:
    print("wrong parameter values")
    
