import os
import requests
import random
import string
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
# Database Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Heroku uses postgres:// but SQLAlchemy needs postgresql://
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to login page if user is not authenticated

# --- API Base URL ---
MAIL_TM_API_URL = "https://api.mail.tm"

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    emails = db.relationship('EmailAccount', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class EmailAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(100), nullable=False)
    mail_tm_id = db.Column(db.String(100), nullable=False) # The ID from mail.tm
    email_address = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False) # The mail.tm password
    token = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Initialization ---
with app.app_context():
    db.create_all()

# --- Helper Functions (Mail.tm) ---
def get_random_domain():
    """Gets a random available domain from mail.tm."""
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(f"{MAIL_TM_API_URL}/domains", headers=headers)
        response.raise_for_status()
        domains_list = response.json()
        domain = random.choice(domains_list)['domain']
        return domain
    except (requests.RequestException, KeyError, IndexError, TypeError) as e:
        print(f"ERROR: Could not fetch domains: {e}")
        return "mail.tm"  # Fallback domain

def create_mail_tm_account():
    """Creates a new email account on mail.tm and returns id, email, password, and token."""
    domain = get_random_domain()
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    email = f"{username}@{domain}"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    try:
        # Create account
        account_data = {'address': email, 'password': password}
        create_response = requests.post(f"{MAIL_TM_API_URL}/accounts", json=account_data, headers=headers)
        
        if create_response.status_code == 429:
            print("ERROR: Rate limit hit while creating account.")
            return 'rate_limited', None, None, None
        if create_response.status_code != 201:
            print(f"ERROR: Error creating account: {create_response.status_code} - {create_response.text}")
            return None, None, None, None
        
        account_info = create_response.json()
        account_id = account_info['id']

        # Get token
        token_data = {'address': email, 'password': password}
        token_response = requests.post(f"{MAIL_TM_API_URL}/token", json=token_data, headers=headers)
        token_response.raise_for_status()
        token = token_response.json()['token']

        return account_id, email, password, token
    except requests.RequestException as e:
        print(f"ERROR: RequestException during account creation: {e}")
        return None, None, None, None

# --- Authentication Routes ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('signup'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Main Application Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/get_emails')
@login_required
def get_emails():
    """Get all email accounts for the logged-in user."""
    email_accounts = EmailAccount.query.filter_by(user_id=current_user.id).all()
    emails_data = [{'id': acc.id, 'nickname': acc.nickname, 'email': acc.email_address} for acc in email_accounts]
    return jsonify(emails_data)

@app.route('/new_email', methods=['POST'])
@login_required
def new_email():
    """Create a new temporary email address using mail.tm."""
    data = request.get_json()
    if not data or 'nickname' not in data:
        return jsonify({'error': 'Nickname is required.'}), 400
    
    nickname = data['nickname']
    existing_email = EmailAccount.query.filter_by(nickname=nickname, user_id=current_user.id).first()
    if existing_email:
        return jsonify({'error': 'Nickname already used.'}), 400

    account_id, email, password, token = create_mail_tm_account()
    if email == 'rate_limited':
        return jsonify({'error': 'Too many requests. Please wait a moment and try again.'}), 429
    if not email:
        return jsonify({'error': 'Failed to create email account from provider.'}), 500

    new_email_account = EmailAccount(
        nickname=nickname,
        mail_tm_id=account_id,
        email_address=email,
        password=password,
        token=token,
        user_id=current_user.id
    )
    db.session.add(new_email_account)
    db.session.commit()

    return jsonify({
        'id': new_email_account.id,
        'nickname': new_email_account.nickname,
        'email': new_email_account.email_address
    })

@app.route('/delete_email', methods=['POST'])
@login_required
def delete_email():
    """Deletes a saved email account by its ID."""
    data = request.get_json()
    email_id = data.get('id')
    if not email_id:
        return jsonify({'error': 'Email ID is required.'}), 400

    email_account = EmailAccount.query.filter_by(id=email_id, user_id=current_user.id).first()
    if not email_account:
        return jsonify({'error': 'Email account not found.'}), 404

    account_id = email_account.mail_tm_id
    token = email_account.token

    try:
        headers = {'Authorization': f'Bearer {token}'}
        # We attempt to delete the account on mail.tm, but proceed even if it fails (e.g., already deleted)
        requests.delete(f"{MAIL_TM_API_URL}/accounts/{account_id}", headers=headers)

        db.session.delete(email_account)
        db.session.commit()

        return jsonify({'message': f'Email {email_account.nickname} deleted successfully.'})
    except requests.RequestException as e:
        # Log the error but still allow deletion from our DB if the user wants it.
        print(f"ERROR: Failed to delete email account from mail.tm: {e}")
        db.session.delete(email_account)
        db.session.commit()
        return jsonify({'message': f'Email {email_account.nickname} deleted from app, but failed to delete from provider.'})



@app.route('/use_email', methods=['POST'])
@login_required
def use_email():
    """Select an email to be the current one by its ID."""
    data = request.get_json()
    email_id = data.get('id')
    if not email_id:
        return jsonify({'error': 'Email ID is required.'}), 400
    
    email_account = EmailAccount.query.filter_by(id=email_id, user_id=current_user.id).first()
    if not email_account:
        return jsonify({'error': 'Email account not found.'}), 404
    
    return jsonify({
        'id': email_account.id,
        'nickname': email_account.nickname,
        'email': email_account.email_address
    })

@app.route('/inbox')
@login_required
def inbox():
    """Get the inbox for a specific email account ID."""
    email_id = request.args.get('id')
    if not email_id:
        return jsonify({'error': 'Email ID is required.'}), 400

    email_account = EmailAccount.query.filter_by(id=email_id, user_id=current_user.id).first()
    if not email_account:
        return jsonify({'error': 'Email account not found.'}), 404
        
    try:
        token = email_account.token
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        response = requests.get(f"{MAIL_TM_API_URL}/messages", headers=headers)
        
        if response.status_code == 429:
            return jsonify({'error': 'Rate limit exceeded.'}), 429
        response.raise_for_status()
        
        messages = response.json()
        adapted_messages = [
            {'id': msg.get('id'), 'from': msg.get('from', {}).get('address', 'Unknown Sender'), 'subject': msg.get('subject', 'No Subject')}
            for msg in messages
        ]
        return jsonify(adapted_messages)
    except (requests.RequestException, KeyError) as e:
        print(f"ERROR fetching inbox for {email_account.email_address}: {e}")
        return jsonify({'error': 'Failed to fetch inbox from provider.'}), 500

@app.route('/read_email')
@login_required
def read_email():
    """Reads a specific email message using its ID."""
    message_id = request.args.get('id')
    email_id = request.args.get('email_id')
    if not message_id or not email_id:
        return jsonify({'error': 'Message ID and Email ID are required.'}), 400

    email_account = EmailAccount.query.filter_by(id=email_id, user_id=current_user.id).first()
    if not email_account:
        return jsonify({'error': 'Email account not found for this user.'}), 404

    try:
        token = email_account.token
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        response = requests.get(f"{MAIL_TM_API_URL}/messages/{message_id}", headers=headers)
        response.raise_for_status()
        
        msg = response.json()
        body = msg.get('html')[0] if msg.get('html') else msg.get('text', 'No content.')
        
        return jsonify({
            'from': msg.get('from', {}).get('address', 'Unknown Sender'),
            'subject': msg.get('subject', 'No Subject'),
            'body': body
        })
    except requests.RequestException as e:
        print(f"ERROR reading email {message_id}: {e}")
        return jsonify({'error': 'Failed to read email from provider.'}), 500

@app.route('/delete_message', methods=['POST'])
@login_required
def delete_message():
    """Deletes a specific email message."""
    data = request.get_json()
    message_id = data.get('id')
    email_id = data.get('email_id')
    if not message_id or not email_id:
        return jsonify({'error': 'Message ID and Email ID are required.'}), 400

    email_account = EmailAccount.query.filter_by(id=email_id, user_id=current_user.id).first()
    if not email_account:
        return jsonify({'error': 'Email account not found for this user.'}), 404

    try:
        token = email_account.token
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.delete(f"{MAIL_TM_API_URL}/messages/{message_id}", headers=headers)
        
        if response.status_code != 204:
            response.raise_for_status()
            
        return jsonify({'message': 'Message deleted successfully.'}), 200
    except requests.RequestException as e:
        print(f"ERROR deleting message {message_id}: {e}")
        return jsonify({'error': 'Failed to delete message from provider.'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
