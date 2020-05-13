from flask import render_template, url_for, flash,redirect, request, abort, Blueprint
from . import main
from ..request import get_article
from ..models import Article, Post
from flask_login import login_required, current_user
from .form import PostForm
from .. import db
from ..auth.form import RegistrationForm

#views
@main.route('/')
def index():
  '''
  view root that returns the index page and various news sources 
  '''
  return render_template('index.html')

@main.route('/international')
def articles():
  '''
  view articles that returns various disaster articles from various sites
  '''
  articles=get_article()
  return render_template('News/articles.html',articles=articles)

@main.route("/about")
def about():
    pass

@main.route("/post")
def post():
  
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    
    return render_template('post.html', posts=posts)

@main.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('main.post'))
    
    return render_template('new_post.html', title='New Post',form=form, legend='New Post')


@main.route("/post/<int:post_id>")
def post(post_id):
    
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


@main.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('main.post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('new_post.html', title='Update Post',form=form, legend='Update Post')


@main.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):

    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
        db.session.delete(post)
        db.session.commit()
    flash('Your post has been deleted!', 'success')
    
    return redirect(url_for('main.post'))
