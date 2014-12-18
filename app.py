import os
import datetime
import requests
from flask import Flask, request, render_template, redirect, url_for, get_flashed_messages, flash
from hashids import Hashids
import json
from bson import ObjectId
from bson.json_util import dumps
import pymongo
from pymongo import Connection
from flask.ext.login import (LoginManager, UserMixin, AnonymousUserMixin,
        current_user, login_user,
        logout_user, user_logged_in, user_logged_out,
        user_loaded_from_cookie, user_login_confirmed,
        user_loaded_from_header, user_loaded_from_request,
        user_unauthorized, user_needs_refresh,
        make_next_param, login_url, login_fresh,
        login_required, session_protected,
        fresh_login_required, confirm_login,
        encode_cookie, decode_cookie, _secret_key, 
        _user_context_processor, user_accessed)
from flask_wtf import Form
from wtforms import StringField, TextField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email
from flask.ext.assets import Environment, Bundle
from flask.ext.wtf.recaptcha import RecaptchaField
from passlib.hash import pbkdf2_sha256, md5_crypt
import scss

SALT="devsalt"

app = Flask(__name__)

# config
app.config.from_pyfile('config.cfg')

# assets
assets = Environment(app)
assets.url = app.static_url_path
scss = Bundle('scss/style.scss', 'scss/normalize.scss', 'scss/type.scss', filters='pyscss', output='css/style.css')
assets.register('scss_all', scss)

# mongo setup
DATABASE_HOST = os.getenv('MONGODB_HOST', 'localhost')
DATABASE_NAME = os.getenv('MONGODB_DATABASE', 'bills')
DATABASE_PORT = int(os.getenv('MONGODB_PORT', 27017)) 

connection = Connection(DATABASE_HOST, DATABASE_PORT)
db = connection[DATABASE_NAME]

users = db.users
bills = db.bills


# classes
class User(UserMixin):
    def __init__(self, email, password):
        self.email = email 
        self.password = password
        self.active = True

    def is_authenticated(self):
        return True

    def is_active(self):
        # Here you should write whatever the code is
        # that checks the database if your user is active
        return True 

    def is_anonymous(self):
        return False

    def get_id(self):
        _id = users.find_one({'email':self.email})['_id']
        return unicode(str(_id))


class FormAddBill(Form):
    amount = TextField('amount', validators=[DataRequired()])
    description = TextField('description', validators=[DataRequired()])
    date = TextField('date', validators=[DataRequired()])
    repeat = SelectField('repeat', choices=[('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('yearly', 'Yearly')])
    comments = TextAreaField('comments', validators=[DataRequired()])


class FormLogin(Form):
    email = TextField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    # recaptcha = RecaptchaField()


class FormSignup(Form):
    email = TextField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    recaptcha = RecaptchaField()


# Creating a login manager instance
login_manager = LoginManager()
# Configuring
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = users.find_one({'_id': user_id})
    return User(user['email'], user['password'])

# methods 
def get_date():
    return str(datetime.datetime.now()).split('.')[0]

def pass_hash(password):
    return pbkdf2_sha256.encrypt(password, rounds=8000, salt_size=16)

def pass_check(email, password):
    password_hashed = users.find_one({'email': email})['password']
    return pbkdf2_sha256.verify(password, password_hashed)

def get_new_id(model, length):
    hashids = Hashids(salt=SALT, min_length=length) 
    try:
        id = model.find({}).count() + 1
    except:
        id = 0
    return hashids.encrypt(id)

# routes 
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/app')
def application():
    if current_user.is_authenticated():
        if bills.find({}):
            user_email = current_user.email
            user_id = users.find_one({'email':user_email})['_id']
            user_bills = bills.find({'user_id':user_id})
        else:
            user_bills = None
        return render_template('app.html', user_bills=user_bills)
    else:
        flash('You need to be logged in to see this page')
        return redirect(url_for('login'))

@app.route('/app/bill/<id>')
def show_bill(id=id):
    if current_user.is_authenticated():
        user_bill = bills.find_one({'_id':id})
        bill_id = user_bill['_id']
        bill_amount = user_bill['amount']
        bill_description = user_bill['description']
        bill_date  = user_bill['date']
        bill_repeat = user_bill['repeat']
        return render_template('show-bill.html', amount=bill_amount, description=bill_description, \
                date=bill_date, repeat=bill_repeat, _id=bill_id)
    else:
        flash('You need to be logged in to see this page')
        return redirect(url_for('login'))

@app.route('/app/bill/new', methods=['GET', 'POST'])
def add_bill():
    form = FormAddBill()
    if current_user.is_authenticated():
        if request.method == 'POST' and 'amount' in request.form:
            user_email = current_user.email
            user_id = users.find_one({'email':user_email})['_id']
            req = request.form
            bill_id = get_new_id(bills, 8)
            bill_amount = req['amount']
            bill_description = req['description']
            bill_date = req['date'] 
            bill_repeat = req['repeat']
            bills.insert({'_id':bill_id, 'user_id':user_id, 'amount':bill_amount, \
                'description':bill_description, 'date':bill_date, 'repeat':bill_repeat})
            flash('Bill created successfully')
            return redirect(url_for('application'))
    else:
        flash('You need to be logged in to see this page')
        return redirect(url_for('login'))
    return render_template('new-bill.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def register():
    form = FormSignup()
    if current_user.is_authenticated():
        return redirect(url_for('show_profile'))
    elif request.method == 'POST' and 'email' in request.form:
        if form.validate_on_submit():
            email = request.form['email']
            password = pass_hash(request.form['password'])
            if users.find_one({'email': email}):
                flash('Email already in use')
            else:
                _id = get_new_id(users, 6)
                users.insert({'_id': _id, 'email':email, 'password':password})
                flash('User created successfully')
                return redirect(url_for('show_profile'))
        else:
            flash('Please enter the information in the form')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FormLogin()
    if current_user.is_authenticated():
        return redirect(url_for('index'))
    elif request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        password = request.form['password']
        hashed_password = pass_hash(password)
        if form.validate_on_submit():
            if users.find_one({'email':email}):
                email = users.find_one({'email':email})['email']
                if pass_check(email, password):
                    user = User(email, hashed_password)
                    if login_user(user):
                        flash('Logged in successfully')
                        return redirect(url_for('show_profile'))
                    else:
                        flash('Sorry, but you couldn\'t log in')
                else:
                    flash('Wrong password')
            else:
                flash('User with that email doesn\'t exist')
        else:
            flash('Please enter your email and password')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
def show_profile():
    if current_user.is_authenticated():
        return render_template('profile.html')
    else:
        flash('You need to be logged in to see the profile page')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
