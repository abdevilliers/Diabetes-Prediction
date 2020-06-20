from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from os import environ
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import pandas as pd
import numpy as np
from sklearn.externals import joblib
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
environ['HI'] = 'christygeorgejoseph@gmail.com'
environ['BYE'] = 'pokemonchristyonid7$'
from flask_mail import Mail, Message



loaded_model = joblib.load('finalizzZed_model.sav')


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site10.db'
db10 = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = environ.get('HI')
app.config['MAIL_PASSWORD'] = environ.get('BYE')
mail = Mail(app)





class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')





class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')






class User(db10.Model):
    id = db10.Column(db10.Integer, primary_key=True)
    username = db10.Column(db10.String(20), unique=True, nullable=False)
    email = db10.Column(db10.String(120), unique=True, nullable=False)
    password = db10.Column(db10.String(60), nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"





@app.route("/")
@app.route("/home")
def home():
    session['logged_in'] = False
    return render_template('home.html')





@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.username.data}!', 'success')
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password = hashed_pw)
        db10.session.add(user)
        db10.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_2 = User.query.filter_by(email=form.email.data).first()
        if user_2 and bcrypt.check_password_hash(user_2.password, form.password.data): 
             session['logged_in'] = True
             flash(f'Successfully logged in as { user_2.username }!', 'success')
             return redirect(url_for('index'))
        else:
            flash(f'Invalid credentials.Please check Username and Password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', title='login', form=form)




@app.route('/predictDiabetes')
def index():
        if session['logged_in'] == True:
           return render_template('index.html')
        else:
            flash(f'You have to login first to view the requested page', 'danger' )
            return redirect(url_for('home'))

@app.route('/predict', methods=['POST'])
def predict():
        if session['logged_in'] == True: 
            l = []
            nm1 = float(request.form['Pregnancies'])
            l.append(nm1)
            nm2 = float(request.form['Glucose Level'])
            l.append(nm2)
            nm3 = float(request.form['Blood Pressure'])
            l.append(nm3)
            nm4 = float(request.form['Skin Thickness'])
            l.append(nm4)
            nm5 = float(request.form['Insulin'])
            l.append(nm5)
            nm6 = float(request.form['BMI'])
            l.append(nm6)
            nm7 = float(request.form['Age'])
            l.append(nm7)
            l = np.array(l)
            l = np.reshape(l,(-1,7))
            pred = loaded_model.predict(l)
            prob_var = loaded_model.predict_proba(l)
            if pred == 0:
                 str = "The person is less likely to suffer from Diabetes in future."
                 percent = int(np.round(prob_var[:,0]*100))
            if pred == 1:
                 str = "The person is more likely to suffer from Diabetes in future."
                 percent = int(np.round(prob_var[:,-1]*100))
            return render_template('results.html', percent=percent, str=str)
        else:
            flash(f'You have to login first to view this page', 'danger' )
            return redirect(url_for('home'))

@app.route('/logout')
def logout():
    if session['logged_in'] == True:
        session['logged_in'] = False
        flash(f'You have been logged out', 'success')
        return redirect(url_for('home'))
     
    else:
        flash(f'You have to login first to view the requested page', 'danger' )
        return redirect(url_for('home'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='christygeorgejoseph@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db10.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)






if __name__ == '__main__':
    app.run(debug=True)