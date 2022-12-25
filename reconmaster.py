import argparse
from flask import render_template,url_for,request,redirect,flash,jsonify
from pandas import read_csv
from app import app,db
from utils.utilities import Helper,Config,Server
from reconnaissance import init_recon
import os
from app.forms import SigninForm,SignupForm
from app.models import User
from flask_login import login_user,login_required,logout_user
from wtforms import ValidationError


ar = argparse.ArgumentParser(description=Helper.LOGO+'List of the Required arguments',formatter_class=argparse.RawTextHelpFormatter)

ar.add_argument("-U","--url", required=True,help="\nEnter Domain name without https or http.(ex- example.com)",type=str)
ar.add_argument("-S","--serveronly",required=False,default=False,help="\nIf you want to run server only(default False)",type=bool)
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
filepath = os.path.join(Config.get_prop('save_path'),urlname)




@app.route('/')
def index():
    return render_template('index.html',urlname=urlname)

@app.route("/signin",methods=["GET","POST"])
def signin():
    form=SigninForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user is not None and user.authenticate_password(form.password.data):
            login_user(user)
            flash("Successfully Signed in")
            nxt=request.args.get("next")
            if nxt is None:
                nxt=url_for('index')
            else:
                 if not nxt[0]=="/":
                    nxt=url_for('index')
            return redirect(nxt)
        else:
            flash("Credientials not matched!!! kindly check username or password")
            return render_template("signin.html",form=form)
    return render_template("signin.html",form=form)


@app.route("/signup",methods=["GET","POST"])
def signup():
    try:
        form=SignupForm()
        if form.validate_on_submit():
            form.is_valid_username()
            form.is_valid_password()
            user=User(form.username.data,form.password.data,form.gender.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration Successfull")
            return redirect(url_for('signin'))
        return render_template("signup.html",form=form)
    except ValidationError as e:
        flash(str(e))
        return render_template("signup.html",form=form)
    


@app.route("/signout")
@login_required
def signout():
    logout_user()
    flash("You are successfully Signed out")
    return redirect(url_for("index"))


@app.route("/dashboard",methods=("POST", "GET"))
@login_required
def dashboard():
    global filepath,urlname
    dirs=[x[1] for x in os.walk(filepath.rsplit("/")[0])]
    if request.method=="POST":
        urlname=request.form['runpath']
        filepath=os.path.join(Config.get_prop('save_path'),urlname)
        return redirect(url_for('index',urlname=urlname))
    else:
        return render_template('dashboard.html',dirs=dirs,urlname=urlname)


@app.route("/subdomain")
@login_required
def subdomain():
    subdomaindata=read_csv(os.path.join(filepath,'subdomain.csv'),on_bad_lines='skip')
    return render_template("subdomain.html",tables=[subdomaindata.to_html(classes="table table-dark",justify="left")],subdomain=urlname,urlname=urlname)

@app.route("/probing")
@login_required
def probing():
    probingdata=read_csv(os.path.join(filepath,'probing.csv'),on_bad_lines='skip')
    count=probingdata['status'].value_counts()
    return render_template("probing.html",tables=[probingdata.to_html(classes="table",justify="left")],Dead=count["Dead"],Live=count["Live"],urlname=urlname)

@app.route("/techstack")
@login_required
def techstacks():
    techstackdata=read_csv(os.path.join(filepath,'techstack.csv'),on_bad_lines='skip')
    return render_template("techstack.html",tables=[techstackdata.to_html(classes="table table-dark",justify="left")],urlname=urlname)

@app.route("/historic",methods=("POST", "GET"))
@login_required
def history():
    def getindexes(page):
        nonlocal historicdatalen
        rows_per_page=2500
        start=rows_per_page*page
        end=start+rows_per_page
        if end>historicdatalen:
            end=historicdatalen
        return page,start,end

    historicdata=read_csv(os.path.join(filepath,'historic.csv'),on_bad_lines='skip')
    historicdatalen=historicdata.shape[0]
    search=""
    page,start,end=getindexes(0)
    if request.method=="GET":
        if "search" in request.args:
            search=request.args["search"]
            if search.strip()!="":
                historicdata=historicdata[historicdata["Historic Data"].str.contains(search)]
                historicdatalen=historicdata.shape[0]
        if "page" in request.args:
            page+=int(request.args["page"])
        page,start,end=getindexes(page)

    return render_template("historical.html",tables=[historicdata.iloc[start:end].to_html(classes="table table-dark",justify="left")],domain=urlname,historicdatalen=historicdatalen,page=page,start=start,end=end,search=search)

@app.route("/portscaning")
@login_required
def scaning():
    scaningdata=read_csv(os.path.join(filepath,'scaning.csv'),on_bad_lines='skip')
    return render_template("portscaning.html",tables=[scaningdata.to_html(classes="table table-dark",justify="left")],urlname=urlname)


@app.route("/logoff")
def logoff():
    server.shutdown()
    return jsonify({"status":"Server Shuted Down Successfully","message":"Thanks For Using Reconmaster"})

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error-404.html'), 404


if __name__=="__main__":
    if not args.serveronly:
        init_recon(args.url,args.engine,filepath)
    server=Server(app,"127.0.0.1",5000)
    server.run()  
