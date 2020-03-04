import json
from flask import Flask, request, flash, url_for, redirect, render_template, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, SubmitField, validators
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

#CHNAGES IN LINE 253, 
app = Flask(__name__)
config_file = "configuration.json"

with open(config_file) as f:
    configuration = json.load(f)
#dburl_str = 'mysql+pymysql://{user}:{password}@{host_name}/{db}'.format(**configuration['database_config'])

#app.config['SQLALCHEMY_DATABASE_URI'] = dburl_str
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
#app.config['SERVER_NAME'] = 'vaccinestories.ischool.syr.edu:80'

### CHECK HOW TO GENERATE SECRET KEY FOR FLASK
app.secret_key = b'\x93t\x81\xce\x92gOeB\xf5\x97_0uY\xb5\x7f\x82\xbf\x02\xaa|\x0cZ'

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

# ----------- Declaration of DB Models ------------------------------------
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, db.Sequence('users_seq'),primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    pwd = db.Column(db.Text)
    verified = db.Column(db.Boolean)
    # mycode
    response =db.relationship('Response',backref='author',lazy=True)
    storypoint= db.relationship('Story',backref='author',lazy=True)


    def set_pwd(self, pwd):
        self.pwd = generate_password_hash(pwd)

    def check_pwd(self, pwd):
        return check_password_hash(self.pwd, pwd)

    def is_verified(self):
        return self.verified

class PostCodes(db.Model):
    __tablename__ = 'posts_codes'
    id = db.Column(db.Integer, db.Sequence('contents_seq'),primary_key=True)
    thread_id = db.Column(db.Integer) # !!! make it foreign to Json table
    post_id = db.Column(db.Integer)
    coded = db.Column(db.String(2048))
    coder = db.Column(db.String(2048))
    coded_date = db.Column(db.DateTime)
    user_response =db.relationship('Response',backref='response')
    user_story=db.relationship('Story',backref='Story')
    
class Response(db.Model):
      __tablename__ = 'Response'
      id = db.Column(db.Integer, db.Sequence('response_seq'),primary_key=True)
      post_id=db.Column(db.Integer, db.ForeignKey('postcodes.id'))
      user_id =db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
      characters=db.Column(db.Text)
      acts=db.Column(db.Text)
      events=db.Column(db.Text)
      consequences=db.Column(db.Text)



class Story(db.Model):
     __tablename__ = 'Story'
     id = db.Column(db.Integer, db.Sequence('story_seq'),primary_key=True)
     post_id=db.Column(db.Integer, db.ForeignKey('postcodes.id'))
     user_id =db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
     characters=db.Column(db.Text)
     acts=db.Column(db.Text)
     events=db.Column(db.Text)
     consequences=db.Column(db.Text)
     story_element = db.Column(db.Text)
     story_point = db.Column(db.Text)
     #categories_described = request.form.getlist("story_points")





    



class JsonData(db.Model):
    __tablename__ = 'table_json'

    id = db.Column(db.Integer,primary_key=True)
    json_data = db.Column(db.JSON)

# ----------- End of declaration of DB Models ------------------------------------

# login form
class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])
    login = SubmitField('Login')


class RegisterForm(Form):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Email()])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm_password', message="Passwords don't match")])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
    register = SubmitField('Register')

class SearchThread(Form):
    search_field = StringField('Enter the value: ', [validators.DataRequired(), validators.Length(min=1, max=5)])
    search = SubmitField('Search')

class FinalCodingForm(Form):
    Characters =StringField('Characters', [validators.DataRequired()])
    Acts=StringField('Acts', [validators.DataRequired()])
    Events=StringField('Events', [validators.DataRequired()])
    Consequences=StringField('Consequences', [validators.DataRequired()])
    Characters2= StringField('Characters2', [validators.DataRequired()])
    Acts2=StringField('Acts2', [validators.DataRequired()])
    Events2=StringField('Events2', [validators.DataRequired()])
    Consequences2=StringField('Consequences2', [validators.DataRequired()])
    story_element= StringField('story_element', [validators.DataRequired()])
    storypoint=StringField('storypoint', [validators.DataRequired()])
    AddAll= SubmitField('AddAll')
    #Addstory =SubmitField('Add a story')


# ----------- End of forms

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

# all the views
@app.route('/')
def start():
    return render_template('index.html')

@app.route('/register')
def register():
    form = RegisterForm()
    return render_template('register.html', form=form)

@app.route('/login')
def login():

    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/FINAL_CODING')
#@login_required
def final_Coding():
    form = FinalCodingForm()
    return render_template('FINAL_CODING.html',form=form)

@app.route('/finalcoding_handler', methods=['POST'])
def finalcoding_handler():
    form = FinalCodingForm(request.form)
    if form.validate():
        Characters =form.Characters.data
        Acts=form.Acts.data
        Events=form.Events.data
        Consequences=form.Consequences.data
        Characters2= form.Characters2.data
        Acts2=form.Acts2.data
        Events2=form.Events2.data
        Consequences2=form.Consequences2.data
        storyelement = form.story_element.data
        storypoint = form.storypoint.data
        response =Response(post_id=post_id, user_id= current_user.id,characters=Characters,acts=Acts, events= Events,consequences=Consequences)
        db.session.add(response)
        db.session.commit()
        story =Story(post_id=post_id, user_id= current_user.id,characters=Characters2,acts=Acts2, events= Events2,consequences=Consequences2,story_element=storyelement,story_point=storypoint)
        db.session.add(story)
        db.session.commit()
    return render_template('index.html', form=form)


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("Logged out......")
    return render_template('index.html')

@app.route('/login_handler', methods=['POST'])
def login_handler():
    form = LoginForm(request.form)
    if form.validate():
        username = form.username.data
        pwd = form.password.data
        # get user
        user = Users.query.filter_by(username=username).first_or_404()
        if user.is_verified() and user.check_pwd(pwd):
            if current_user.is_authenticated:
                logout_user()

            login_user(user)
            flash("Logged in success ........")
            search_thread_form = SearchThread()
            return render_template('search.html', form=search_thread_form)
    flash("Something is not correct in login ........")
    return render_template('login.html', form=form)

@app.route('/search_thread')
@login_required
def search_thread():
    search_thread_form = SearchThread()
    return render_template('search.html', form=search_thread_form)

@app.route('/register_handler', methods=['POST'])
def register_handler():
    form = RegisterForm(request.form)
    if form.validate():
        if current_user.is_authenticated:
            logout_user()

        username = form.username.data
        email = form.email.data

        # get user
        try:
            user = Users(username=username, email=email, verified=False)
            user.set_pwd(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration is pending......")
            return render_template('index.html')
        except:
            flash('Error in registration form information! Contact for help.')
            return redirect(url_for('register'))

    flash('Error in registration!')
    return redirect(url_for('register'))

@app.route('/submit_code', methods=['POST'])
@login_required
def submit_code():
    result = request.form.to_dict()
    goToSearch = False
    if 'formSubmit' in result:
        result.pop('formSubmit')
        goToSearch = True

    thread = result.pop('thread')

    for k,v in result.items():
        post_id = k.split('_')[1]
        code_value = v
        contentCode = PostCodes(thread_id=thread, post_id=post_id, coded=code_value, coded_date=datetime.today(), coder=current_user.username)
        db.session.add(contentCode)
        db.session.commit()

    if goToSearch:
        flash("Submit success ........")
        search_thread_form = SearchThread()
        return render_template('search.html', form=search_thread_form)
    else:
        result = JsonData.query.filter_by(id=thread).first_or_404()
        coded_result = PostCodes.query.filter_by(thread_id=thread, coder=current_user.username)
        earlier_coded = {}

        for r in coded_result:
            earlier_coded[r.post_id] = r.coded

        posts_stack = result.json_data['posts'][:]

        while len(posts_stack)>0:
            post = posts_stack.pop()
            post['coded'] = earlier_coded.get(post['id'], None)
            children = post['replies']
            for c in children:
                posts_stack.insert(0, c)

        return jsonify(result.json_data)

@app.route('/search_handler', methods=['POST'])
@login_required
def search_handler():

    form = SearchThread(request.form)
    if form.validate():
        thread_id = form.search_field.data
        result = JsonData.query.filter_by(id=thread_id).first_or_404()
        coded_result = PostCodes.query.filter_by(thread_id=thread_id, coder=current_user.username)
        earlier_coded = {}

        for r in coded_result:
            earlier_coded[r.post_id] = r.coded

        posts_stack = result.json_data['posts'][:]

        while len(posts_stack)>0:
            post = posts_stack.pop()
            post['coded'] = earlier_coded.get(post['id'], None)
            children = post['replies']
            for c in children:
                posts_stack.insert(0, c)

        return render_template('threads.html', result = result.json_data)

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=8)


@app.errorhandler(404)
def page_not_found(e):

    flash('Cannot process request. Something was wrong .....')
    return render_template('index.html'), 404

@app.errorhandler(401)
def page_not_login(e):

    flash('You are not logged in. You MUST login .....')
    return render_template('index.html'), 401





#§  if __name__ == '__main__':
   #db.create_all()
   #app.run(host='0.0.0.0', port=80)


