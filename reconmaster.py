import argparse
from flask import Flask,render_template,url_for,request,redirect
from pandas import read_csv
from utils import utilities
from reconnaissance import init_recon
import os



ar = argparse.ArgumentParser(description=utilities.Helper.LOGO+'List of the Required arguments',formatter_class=argparse.RawTextHelpFormatter)

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
urlname=args.url.split('.')[0]
filepath = os.path.join(utilities.Config.get_prop('save_path'),urlname)
app = Flask(__name__,static_folder='templates/assets')
app.config['SECRET_KEY']=os.urandom(24).hex()
logger = utilities.Helper.LOGGER



@app.route('/')
def index():
    return render_template('index.html',urlname=urlname)

@app.route("/dashboard",methods=("POST", "GET"))
def dashboard():
    global filepath,urlname
    dirs=[x[1] for x in os.walk(filepath.rsplit("/")[0])]
    if request.method=="POST":
        urlname=request.form['runpath']
        filepath=os.path.join(utilities.Config.get_prop('save_path'),urlname)
        return redirect(url_for('index',urlname=urlname))
    else:
        return render_template('dashboard.html',dirs=dirs,urlname=urlname)


@app.route("/subdomain")
def subdomain():
    subdomaindata=read_csv(os.path.join(filepath,'subdomain.csv'),on_bad_lines='skip')
    return render_template("subdomain.html",tables=[subdomaindata.to_html(classes="table table-dark",justify="left")],subdomain=urlname,urlname=urlname)

@app.route("/probing")
def probing():
    probingdata=read_csv(os.path.join(filepath,'probing.csv'),on_bad_lines='skip')
    count=probingdata['status'].value_counts()
    return render_template("probing.html",tables=[probingdata.to_html(classes="table",justify="left")],Dead=count["Dead"],Live=count["Live"],urlname=urlname)

@app.route("/techstack")
def techstacks():
    techstackdata=read_csv(os.path.join(filepath,'techstack.csv'),on_bad_lines='skip')
    return render_template("techstack.html",tables=[techstackdata.to_html(classes="table table-dark",justify="left")],urlname=urlname)

@app.route("/historic",methods=("POST", "GET"))
def history():
    historicdata=read_csv(os.path.join(filepath,'historic.csv'),on_bad_lines='skip')
    if request.method=="GET":
        if "search" in request.args:
            historicdata=historicdata[historicdata["Historic Data"].str.contains(request.args["search"])]
    return render_template("historical.html",tables=[historicdata.to_html(classes="table table-dark",justify="left")],domain=urlname,urlname=urlname)

@app.route("/portscaning")
def scaning():
    scaningdata=read_csv(os.path.join(filepath,'scaning.csv'),on_bad_lines='skip')
    return render_template("portscaning.html",tables=[scaningdata.to_html(classes="table table-dark",justify="left")],urlname=urlname)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error-404.html'), 404


if __name__=="__main__":
    init_recon(args.url,args.engine,filepath)
    app.run()
