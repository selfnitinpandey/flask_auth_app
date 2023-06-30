from flask import Flask ,render_template,redirect,url_for,request,flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin,LoginManager,login_required,current_user,login_user,logout_user
from datetime import datetime

app=Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/flask_auth_app'
db=SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view ='login'
login_manager.init_app(app)

# User table models
class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(100),unique=True)
    password=db.Column(db.String(100))
    name=db.Column(db.String(100))

# Blog table model
class Blog(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100))
    content=db.Column(db.String(800))
    created_at=db.Column(db.DateTime(),default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# index page
@app.route('/')
def index():
    blog_list = Blog.query.all()
    return render_template('index.html', blog_list=blog_list)

# profile page
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html',name=current_user.name)

# login page
@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()
        if email=='' or password=='':
            flash('Please Enter email and password Fields','warning')
            return redirect(url_for('login'))
        else:
            if user:
                if not user or not check_password_hash(user.password,password):
                    flash('Please Check Your login details and try again','warning')
                    return redirect(url_for('login'))
                else:
                    login_user(user)
                    return redirect(url_for('profile'))
            else:
                flash('Email address Does not exists,Make an Account','success')
                return redirect(url_for('signup'))
    else:
        return render_template('login.html')

# signup page
@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name=request.form.get('name')
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()
        if name=='' or email=='' or password=='':
            flash('Please Enter all fields to register here', 'warning')
            return redirect(url_for('signup'))
        if user:
            flash('Email address already exists','warning')
            return redirect(url_for('signup'))
        else:
            password=generate_password_hash(password,method="sha256")
            print(password)
            newuser=User(email=email,name=name,password=password)
            db.session.add(newuser)
            db.session.commit()
            flash('You have registered Successfully','success')
            return redirect(url_for('login'))
    else:
        return render_template('signup.html')

# logout page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out successfully','success')
    return redirect(url_for('login'))

# bloging url here ----------------------------------------
@app.route('/createblog',methods=['POST','GET'])
@login_required
def blog():
    if request.method == 'POST':
        title=request.form.get('title')
        content=request.form.get('content')
        author_id=current_user.id
        blog=Blog(title=title,content=content,author_id=author_id)
        db.session.add(blog)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('blog.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)