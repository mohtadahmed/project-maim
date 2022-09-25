import os
import json

import PyPDF2
from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

migrate = Migrate(app, db)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    password_confirm = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    student_id = db.Column(db.Integer, nullable=False, unique=True)
    mobile_number = db.Column(db.Integer, nullable=False, unique=True)


class PrintQueue(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    customer = db.relationship(lambda: User, uselist=False)
    file_name = db.Column(db.String(120), nullable=False, unique=False, default='Not Set')
    file_location = db.Column(db.String(520), nullable=False, default='')
    total_copies = db.Column(db.Integer, nullable=False, unique=False, default='1')
    pages = db.Column(db.String(120), nullable=False, unique=False, default='0')
    total_cost = db.Column(db.Float, nullable=False, unique=False, default=0)
    print_progress_status = db.Column(db.String(120), nullable=False, unique=False, default='waiting for verification')
    payment_method = db.Column(db.String(120), nullable=False, unique=False, default='')
    account = db.Column(db.String(120), nullable=False, unique=False, default='')
    payment_transaction_id = db.Column(db.String(120), nullable=False, default='')
    payment_verification_status = db.Column(db.String(120), nullable=False, unique=False, default='pending')

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}


admin = Admin(app, name='microblog', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(PrintQueue, db.session))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasceretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=200)], render_kw={"placeholder": "Enter Your Full Name"})

    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20), validators.EqualTo('password_confirm', message='Passwords must match')], render_kw={"placeholder": "Password"})

    password_confirm = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Confirm Your Password"})

    email = StringField(validators=[InputRequired(), Length(
        min=10, max=120)], render_kw={"placeholder": "Email Address"})

    student_id = StringField(validators=[InputRequired(), Length(
        min=4, max=8)], render_kw={"placeholder": "Enter Your ID Number"})

    mobile_number = StringField(validators=[InputRequired(), Length(
        min=4, max=12)], render_kw={"placeholder": "Enter Your Mobile Number"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exist. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@ app.route('/')
@login_required
def home():
    if current_user.get_id():
        return redirect('/dashboard')
    else:
        return redirect('/login')


@ app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/dashboard')
    return render_template('login.html', form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = current_user.get_id()
    prev_files = PrintQueue.query.filter_by(customer_id=user_id).order_by(PrintQueue.id).all()
    data = [dict(id=row.id,
                 file_name=row.file_name,
                 src=row.file_location,
                 payment_status=row.payment_verification_status,
                 print_status=row.print_progress_status) for row in prev_files]

    return render_template('dashboard.html', data=data)


@app.route("/uploader", methods=['GET', 'POST'])
@login_required
def upload_file():
    username = current_user.username
    file_upload_path = os.path.join('static', 'upload', 'file', username)
    os.makedirs(file_upload_path, exist_ok=True)

    file = request.files['file']
    file_name = file.filename
    file_path = os.path.join(file_upload_path, file_name)
    file.save(file_path)
    data = {
            "customer_id": current_user.get_id(),
            "file_location": file_path,
            'file_name': file_name
        }
    data_query = PrintQueue(**data)
    db.session.add(data_query)
    db.session.commit()
    db.session.flush()
    record_id = data_query.id
    return redirect(f'/set_options/{record_id}')


@app.route("/set_options/<record_id>", methods=['GET', 'POST'])
@login_required
def set_options(record_id):
    rec = PrintQueue.query.filter_by(id=record_id).first()
    if not rec:
        return redirect('/dashboard')

    if int(current_user.get_id()) != int(rec.customer_id):
        return f'You are not allowed to edit this file.'

    file_path = rec.file_location
    if file_path[0] != '/':
        file_path = '/' + file_path

    with open(file_path[1:], mode='rb') as pdf:
        pdfdoc = PyPDF2.PdfFileReader(pdf)
        pg = pdfdoc.numPages

    return render_template('set_options.html',
                           pageNumber=pg,
                           filename=rec.file_name,
                           filePath=file_path,
                           unit_price=3,
                           record_id=record_id,
                           username=current_user.name,
                           user_id=current_user.get_id())


@app.route("/doc_to_print", methods=['GET'])
def get_data_to_print():
    data = PrintQueue.query.filter(
            PrintQueue.print_progress_status == 'in queue' and \
            PrintQueue.payment_verification_status == 'verified').order_by(PrintQueue.id).all()
    data = [dict(id=row.id, pages=row.pages, src=row.file_location, copies=row.total_copies) for row in data]
    return jsonify(data)


@app.route("/accept_print_info/<record_id>", methods=['POST'])
def print_details(record_id):
    data = request.form.to_dict()
    PrintQueue.query.filter_by(id=int(record_id)).update(data)
    db.session.commit()
    return "accepted"


@app.route("/delete_print_request/<record_id>", methods=['GET'])
def delete_request(record_id):
    delete_req = PrintQueue.query.filter_by(id=int(record_id))
    try:
        file_loc = delete_req.first().file_location
        os.remove(file_loc)
        delete_req.delete()
        db.session.commit()
        return redirect('/dashboard')
    except Exception as e:
        print("Deletion failed", e)
        return 'failed'


@app.route("/print_success", methods=['POST'])
def print_success():
    task_id = json.loads(request.data)['task_id']
    PrintQueue.query.filter_by(id=task_id).update(dict(print_progress_status='completed'))
    db.session.commit()
    return 'updated'


@ app.route("/logout", methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data, username=form.username.data,
                        password=hashed_password, password_confirm=hashed_password, email=form.email.data, student_id=form.student_id.data, mobile_number=form.mobile_number.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('registration.html', form=form)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
