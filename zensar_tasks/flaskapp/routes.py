from flask import flash, redirect, render_template, session, url_for, request, jsonify
from flaskapp.forms import LoginForm
from manage import app
from flaskapp.forms import LoginForm
import datetime
import jwt
from functools import wraps

def token_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            token = request.args['token']
        except:
            flash('Please login', 'danger')
            return redirect(url_for('login'))
        if not token:
            return jsonify({'Alert':'Invalid Token'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], 'HS256')
        except:
            return jsonify({'message':'Token Expired'}), 403
        return func(*args, **kwargs)
    return wrapped


@app.route('/user', methods = ['POST','GET'])
@token_required
def user():
    try:
        username = request.args['username']
        return render_template('user.html', title = 'user', data = username)
    except:
        return redirect(url_for('login'))


@app.route('/login', methods = ['POST', "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data and form.password.data :
            session['logged_in'] = True
            token = jwt.encode({
                'user':form.username.data,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds = 60)
            }, app.config['SECRET_KEY'])
            flash('you have been logged in!', 'success')
            return redirect(url_for('user', token = token, username = form.username.data))
        else:
            flash('Login unsuccesful!')
    return render_template('login.html', title = 'login', form = form)

@app.route('/')
def home():
    return redirect(url_for('login'))