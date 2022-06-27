import argparse
from flask import Flask,render_template,url_for,session
from pandas import read_csv
from utils import helper
from reconnaissance import init_recon
import os



ar = argparse.ArgumentParser(description=helper.LOGO+'List of the Required arguments',formatter_class=argparse.RawTextHelpFormatter)

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
filepath = os.path.join(helper.get_config('save_path'),args.url.split('.')[0])
app = Flask(__name__,static_folder='templates/assets')
logger = helper.LOGGER



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
    init_recon(args.url,args.engine,filepath)
    app.run()