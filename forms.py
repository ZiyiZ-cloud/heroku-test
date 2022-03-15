
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, EmailField, PasswordField, HiddenField
from wtforms.validators import InputRequired


class RegisterForm(FlaskForm):
    
    username = StringField('Username',
                       validators = [InputRequired()])
    password = PasswordField('Password',
                         validators = [InputRequired()])
    email = EmailField('Email',
                      validators = [InputRequired()])
    first_name = StringField('First Name',
                       validators = [InputRequired()])
    last_name = StringField('Last Name',
                        validators = [InputRequired()])
    
    
    
    
class LoginForm(FlaskForm):
    
    username = StringField('Username',
                       validators = [InputRequired()])
    password = PasswordField('Password',
                         validators = [InputRequired()])
    

class DogSearchForm(FlaskForm):
    
    address = IntegerField('Enter Zipcode',
                           validators = [InputRequired()])
    radius = IntegerField('Enter the radius',
                          validators = [InputRequired()])

class CatSearchForm(FlaskForm):
    
    address = IntegerField('Enter Zipcode',
                           validators = [InputRequired()])
    radius = IntegerField('Enter the radius',
                          validators = [InputRequired()])
