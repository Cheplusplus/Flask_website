from flask import Flask, redirect, render_template, flash, request, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from bcrypt import checkpw, hashpw, gensalt
from forms import LoginForm, SignUpForm


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'development key'
# app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    products = db.Column(db.Text)

    def __repr__(self):
        return f'<User {self.username}>'

    def add_product(self, product_id):
        if self.products:
            self.products += ',' + str(product_id)
        else:
            self.products = ',' + str(product_id)

    def remove_product(self, product_id):
        self.products = self.products.replace(',' + str(product_id), '', 1)

    def product_list(self):
        if self.products:
            return self.products.split(sep=',')
        else:
            return []


def add_user(username, password):
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    return new_user


def create_app_context():
    with app.app_context():
        db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')


@app.route('/')
def home():
    if current_user.is_anonymous:
        user = "Guest"
    else:
        user = current_user.username
    messages = get_flashed_messages()
    return render_template('index.html', messages=messages, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if request.method == 'POST':
        if not form.validate_on_submit():
            flash('All fields are required')
            message = get_flashed_messages()
            return render_template('login.html', messages=messages, form=form)

        username = form.username.data
        password = form.password.data
        password_bytes = password.encode('utf-8')

        user = User.query.filter_by(username=username).first()
        if not user:
            pass
        elif checkpw(password_bytes, user.password):
            login_user(user)
            flash('Login Successful')
            messages = get_flashed_messages()
            return render_template('index.html', messages=messages)
        
        flash('Invalid username or password')
    messages = get_flashed_messages()
    return render_template('login.html', messages=messages,form=form)
   
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if request.method == 'POST':
        if not form.validate_on_submit():
            flash('All fields are required')
            message = get_flashed_messages()
            return render_template('signup.html', messages=messages, form=form)

        username = form.username.data
        password = form.password.data
        password_bytes = password.encode('utf-8')

        salt = gensalt()
        password = hashpw(password_bytes, salt)

        user = User.query.filter_by(username=username).first()
        if user is not None:
            flash('Username is already taken')
        else:
            user = add_user(username, password)
            flash('Successfully created account')
            login_user(user)
            return redirect('/')
    messages = get_flashed_messages()
    return render_template('signup.html', messages=messages, form=form)

@app.route('/add/<product_id>')
@login_required
def add_product(product_id):
    current_user.add_product(product_id)
    db.session.commit()
    flash(f"product: {product_id.upper()} added to your products")
    return redirect('/')

@app.route('/remove/<product_id>')
@login_required
def remove_product(product_id):
    current_user.remove_product(product_id)
    db.session.commit()
    flash(f"product: {product_id.upper()} removed to your products")
    return redirect ('/profile')

@app.route('/profile')
@login_required
def show_profile():
    return render_template('profile.html')


if __name__ == "__main__":
    create_app_context()
    app.run()
