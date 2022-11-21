from wtforms import StringField,PasswordField,ValidationError,SubmitField,SelectField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired,EqualTo
from app.models import User

class SignupForm(FlaskForm):
    username=StringField("Enter Username",validators=[DataRequired()])
    password=PasswordField("Enter Password",validators=[DataRequired(),EqualTo('conf_password','Password Must Match!!')])
    gender=SelectField("Select Gender",choices=[("Male",'Male'),("Female","Female"),("Lgtv","Lgtv")],validators=[DataRequired()])
    conf_password=PasswordField("Enter Password Again",validators=[DataRequired()])
    submit=SubmitField("Signup")

    def is_valid_username(self):
        user=User.query.filter_by(username=self.username.data).first()
        if not (self.username.data is not None and 5<len(self.username.data)<=72):
            raise ValidationError("Username must be 6 Character Long and Do not exceed Till 72 Characters")
        if user:
            raise ValidationError("Username already registered!!!!")
            

    def is_valid_password(self):
        if not (self.password.data is not None and 5<len(self.password.data)<=72):
           raise ValidationError("Password must be 6 Character Long and Do not exceed Till 72 Characters")

class SigninForm(FlaskForm):
    username=StringField("Enter Username",validators=[DataRequired()])
    password=PasswordField("Enter Password",validators=[DataRequired()])
    submit=SubmitField("Signin")