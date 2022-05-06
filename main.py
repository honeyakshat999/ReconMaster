import argparse
from flask import Flask,render_template,url_for,session
import requests
from subdomain import writestatus
from get_config import get_config
from probing import init_prob
import os
from techstack import techstack
from historic import historic
from pandas import read_csv
from portscaning import portscaning
from get_config import get_config

apierrors={}
logo="""
   __                                          _            
  /__\ ___  ___ ___  _ __  _ __ ___   __ _ ___| |_ ___ _ __ 
 / \/// _ \/ __/ _ \| '_ \| '_ ` _ \ / _` / __| __/ _ \ '__|
/ _  \  __/ (_| (_) | | | | | | | | | (_| \__ \ ||  __/ |   
\/ \_/\___|\___\___/|_| |_|_| |_| |_|\__,_|___/\__\___|_|   
    \n\n"""

ar = argparse.ArgumentParser(description=logo+'List of the Required arguments',formatter_class=argparse.RawTextHelpFormatter)

ar.add_argument("-U","--url", required=True,help="\nEnter Domain name without https or http.(ex- example.com)",type=str)
ar.add_argument("-E","--engine", required=False,help="""\nWhere to collect data. 
used 'all'(default) keyword to use every search engine.\n
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
filepath=os.path.join(get_config('save_path'),args.url.split('.')[0])
app=Flask(__name__,static_folder='templates/assets')

def getkey(keyname):
    _loc=get_config("key")
    with open(_loc,'r') as file:
        data={k.strip():v.strip() for k,v in [x.split(':') for x in file.read().splitlines()]}
    if keyname=='all':
        return data
    return data.get(keyname)

def checkkeys():
    keys=getkey('all')
    global apierrors
    for x in keys:
        y=x.split('_')[0]
        if keys[x] is None or keys[x]=='':
            apierrors[y]="No API Keys Found!!"
        else:
            if y=='shodan':
                if requests.get(f"https://api.shodan.io/shodan/host/8.8.8.8?key={keys[x]}").status_code!=200:
                    apierrors[y]="Invalid API Keys!!"
            elif y=='binaryedge':
                if requests.get('https://api.binaryedge.io/v2/user/subscription',headers={'X-Key':f"{keys[x]}"}).status_code!=200:
                    apierrors[y]="Invalid API Keys!!"
            elif y=='virustotal':
                if requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={keys[x]}").status_code!=200:
                    apierrors[y]="Invalid API Keys!!"
            elif y=='securitytrails':
                if requests.get("https://api.securitytrails.com/v1/history/trello.com/dns/a",headers={'Content-Type':"application/json",'apikey':f"{keys[x]}"}).status_code!=200:
                    apierrors[y]="Invalid API Keys!!"

      
        
def displaystatus():
    checkkeys()
    global apierrors
    print(logo+"Engines\t\t\tStatus\t\tReason\n")
    for x in ['google','bing','duckduckgo','alienvault','urlscan','threatcrowd','rapiddns','shodan','virustotal','securitytrails','binaryedge']:
        if x in apierrors:
            print(f"{x:<15}\t\tInactive\t{apierrors[x]}")
        else:
            print(f"{x:<15}\t\tActive")


@app.route('/')
def index():
    return render_template('index.html')

@app.route("/subdomain",methods=("POST", "GET"))
def subdomain():
    subdomaindata=read_csv(os.path.join(filepath,'subdomain.csv'))
    return render_template("subdomain.html",tables=[subdomaindata.to_html(classes="table table-dark",justify="left")],subdomain=args.url.split('.')[0])

@app.route("/probing",methods=("POST", "GET"))
def probing():
    probingdata=read_csv(os.path.join(filepath,'probing.csv'))
    count=probingdata['status'].value_counts()
    return render_template("probing.html",tables=[probingdata.to_html(classes="table",justify="left")],Dead=count["Dead"],Live=count["Live"])

@app.route("/techstack")
def techstacks():
    techstackdata=read_csv(os.path.join(filepath,'techstack.csv'))
    return render_template("techstack.html",tables=[techstackdata.to_html(classes="table table-dark",justify="left")])

@app.route("/historic")
def history():
    historicdata=read_csv(os.path.join(filepath,'historic.csv'),on_bad_lines='skip')
    return render_template("historical.html",tables=[historicdata.to_html(classes="table table-dark",justify="left")],domain=args.url.split('.')[0])

@app.route("/portscaning")
def scaning():
    scaningdata=read_csv(os.path.join(filepath,'scaning.csv'))
    return render_template("portscaning.html",tables=[scaningdata.to_html(classes="table table-dark",justify="left")])

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error-404.html'), 404

if __name__=="__main__":
    if os.path.exists(filepath):
        app.run()
    else:
        cwd=os.getcwd()
        os.chdir(f'{cwd}/results')
        os.system(f"mkdir {args.url.split('.')[0]}")
        os.chdir(cwd)
        displaystatus()
        writestatus(args.url,args.engine,filepath,apierrors,getkey('all'))
        init_prob(filepath)
        techstack(filepath)
        historic(args.url,filepath)
        portscaning(args.url,filepath,3)
        app.run()