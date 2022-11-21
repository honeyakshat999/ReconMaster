from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os


app = Flask(__name__,static_folder='templates/assets',template_folder="templates")
app.config['SECRET_KEY']=os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path.rstrip("\\app\\instance"), 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db=SQLAlchemy(app)
Migrate(app,db)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="signin"


from app.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)