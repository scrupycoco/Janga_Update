import flask
from flask import render_template, redirect, url_for, flash,request
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from ..models import User,Post
from .form import RegistrationForm, LoginForm
from .. import db, bcrypt
from app.auth.form import RequestResetForm, ResetPasswordForm, UpdateAccountForm
from app.auth.utils import save_picture, send_reset_email
from app.request import get_quote


@auth.route("/register", methods=['GET', 'POST'])
def register():
    quote = get_quote()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data, 
            email=form.email.data, 
            password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html', title='Register', form=form, quote=quote)


@auth.route("/login", methods=['GET', 'POST'])
def login():
    quote = get_quote()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html', title='Login', form=form, quote=quote)


@auth.route("/logout")
def logout():
    quote = get_quote()
    logout_user()
    return redirect(url_for('main.home'))


@auth.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    quote = get_quote()
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    
    return render_template('account.html', title='Account',image_file=image_file, form=form, quote=quote)


@auth.route("/user/<string:username>")
def user_posts(username):
    quote = get_quote()
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    
    return render_template('user_posts.html', posts=posts, user=user , quote=quote)


@auth.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    quote = get_quote()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_request.html', title='Reset Password', form=form, quote=quote)


@auth.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    quote = get_quote()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_token.html', title='Reset Password', form=form, quote=quote)