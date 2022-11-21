from app import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash,generate_password_hash


class User(db.Model,UserMixin):

    __tablename__="users"
    
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(45),unique=True)
    password=db.Column(db.String(72))
    gender=db.Column(db.String(6))

    def __init__(self,username,password,gender):
        self.username=username
        self.gender=gender
        self.password=generate_password_hash(password)
        
    def authenticate_password(self,password):
        return check_password_hash(self.password,password)
