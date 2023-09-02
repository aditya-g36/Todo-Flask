from flask import Flask ,redirect,url_for,render_template,request,session,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy import desc
from flask_caching import Cache
app=Flask(__name__)
cache = Cache(config={'CACHE_TYPE':'RedisCache','CACHE_REDIS_HOST':'0.0.0.0','CACHE_REDIS_PORT':6379})
cache.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///Task.db'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///User.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=True
app.config["SECRET_KEY"]="hhfjksjf"

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

headings=["Task","Edit","Remove"]

global found_user
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(10000))
    user_id = db.Column(db.String(150))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit=SubmitField("Login")

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login",methods=["POST","GET"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        session["user"]=form.username
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for("insert"))
    return render_template("log.html",form=form)

@app.route("/signup",methods=["POST","GET"])
def signup():

    form=RegisterForm()
    if form.validate_on_submit():
        session["user"]=form.username
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("insert"))
    return render_template("signup.html",form=form)

@app.route('/insert',methods=["POST","GET"])
@login_required
def insert():
    iden=session["user"]
    if request.method =="POST":
        user=request.form["nm"]
        
        fill=Task(todo=user,user_id=iden)
        db.session.add(fill)
        db.session.commit()
        cache.clear()
        return redirect(url_for("insert"))
    else: 
        checker=cache.get(str(iden))
        if checker:
            return render_template("addtask.html",headings=headings,value=checker,iden=iden)    
        value = Task.query.order_by(desc(Task.id)).all()
        cache.set(str(iden),value)
        return render_template("addtask.html",headings=headings,value=value,iden=iden)

@app.route('/delete/<int:row>')
def delete(row):
    Task.query.filter_by(id=row).delete()
    db.session.commit()
    cache.clear()
    return redirect(url_for("insert"))

@app.route('/update/<int:row>',methods=["POST","GET"])
def update(row):
    upda=request.form["up"]
    temp=Task.query.filter_by(id=row).first()
    temp.todo=upda
    db.session.commit()
    cache.clear()
    return redirect(url_for("insert"))

@app.route('/logout')
@login_required
def logout():
    flash("You have been logout!")
    session.pop("user",None)
    logout_user()
    return redirect(url_for("login"))
    
if __name__ =="__main__":
    with app.app_context():
        db.create_all()
    app.run("0.0.0.0",debug=True)