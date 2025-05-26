from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate  # Add this import
import os
from datetime import datetime
from flask_migrate import Migrate  # Add this import

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
migrate = Migrate(app, db)




# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# Models
class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    phone = db.Column(db.String(20), nullable=True)  # New optional field
    name = db.Column(db.String(100), nullable=True)  # New optional field
    ip_hash = db.Column(db.String(64))  # For basic spam protection

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))  # Make sure this column exists
    is_superadmin = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)

    # Add these methods:
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
def update_database():
    with app.app_context():
        # Check if the new columns exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        
        # Add columns to Suggestion table if they don't exist
        if 'phone' not in inspector.get_columns('suggestion'):
            db.engine.execute('ALTER TABLE suggestion ADD COLUMN phone VARCHAR(20)')
        if 'name' not in inspector.get_columns('suggestion'):
            db.engine.execute('ALTER TABLE suggestion ADD COLUMN name VARCHAR(100)')
        if 'ip_hash' not in inspector.get_columns('suggestion'):
            db.engine.execute('ALTER TABLE suggestion ADD COLUMN ip_hash VARCHAR(64)')
            
        # Add columns to Admin table if they don't exist
        if 'is_superadmin' not in inspector.get_columns('admin'):
            db.engine.execute('ALTER TABLE admin ADD COLUMN is_superadmin BOOLEAN DEFAULT FALSE')
        if 'created_by' not in inspector.get_columns('admin'):
            db.engine.execute('ALTER TABLE admin ADD COLUMN created_by INTEGER')
            
        # Make the first admin a superadmin
        first_admin = Admin.query.first()
        if first_admin and not first_admin.is_superadmin:
            first_admin.is_superadmin = True
            db.session.commit()
    
    
@app.route('/admin/create', methods=['GET', 'POST'])
@login_required
def create_admin():
    with app.app_context():
        if not Admin.query.first():
            admin = Admin(
                username='admin',
                is_superadmin=True
            )
            admin.set_password('admin123')  # Use the set_password method
            db.session.add(admin)
            db.session.commit()
            print("Superadmin created. Username: admin, Password: admin123")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_superadmin = bool(request.form.get('is_superadmin'))

        if Admin.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            new_admin = Admin(
                username=username,
                is_superadmin=is_superadmin,
                created_by=current_user.id
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin account created successfully', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin/create_admin.html')

@app.route('/admin/list')
@login_required
def admin_list():
    if not current_user.is_superadmin:
        flash('Only superadmins can view admin list', 'error')
        return redirect(url_for('admin_dashboard'))

    admins = Admin.query.all()
    admin_data = []
    for admin in admins:
        creator = Admin.query.get(admin.created_by).username if admin.created_by else 'System'
        admin_data.append({
            'id': admin.id,  # Include the admin ID
            'username': admin.username,
            'is_superadmin': admin.is_superadmin,
            'created_by': creator
        })

    return render_template('admin/list.html', admins=admin_data)

# Refactor load_user to include error handling
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(Admin, int(user_id))
    except (ValueError, TypeError):
        return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Enhance the submit route
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        message = request.form.get('message')
        phone = request.form.get('phone', '').strip() or None  # Optional
        name = request.form.get('name', '').strip() or None    # Optional

        # Validate phone number (basic validation for digits and optional +)
        if phone and not phone.replace('+', '').isdigit():
            flash('Invalid phone number format', 'error')
            return redirect(url_for('submit'))

        # Prevent duplicate submissions from the same IP within 5 minutes
        ip_hash = generate_password_hash(request.remote_addr, method='pbkdf2:sha256')
        recent_suggestion = Suggestion.query.filter_by(ip_hash=ip_hash).order_by(Suggestion.timestamp.desc()).first()
        if recent_suggestion and (datetime.utcnow() - recent_suggestion.timestamp).total_seconds() < 300:
            flash('You can only submit one suggestion every 5 minutes', 'error')
            return redirect(url_for('submit'))

        if message and len(message.strip()) > 0:
            new_suggestion = Suggestion(
                message=message.strip(),
                phone=phone,
                name=name,
                ip_hash=ip_hash  # Use the hashed IP for spam protection
            )
            db.session.add(new_suggestion)
            db.session.commit()
            flash('Your suggestion has been submitted!', 'success')
            return redirect(url_for('submit'))
        else:
            flash('Please enter a message', 'error')
    return render_template('submit.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('admin_login.html')


@app.route('/admin/clear', methods=['POST'])
@login_required
def clear_suggestions():
    try:
        # Delete all suggestions
        num_deleted = db.session.query(Suggestion).delete()
        db.session.commit()
        flash(f'Successfully deleted {num_deleted} suggestions', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error clearing suggestions', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('reset_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('reset_password'))
            
        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('reset_password'))
            
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('reset_password'))
            
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('reset_password.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    suggestions = Suggestion.query.order_by(Suggestion.timestamp.desc()).all()
    today = datetime.now().date()
    today_count = Suggestion.query.filter(
        db.func.date(Suggestion.timestamp) == today
    ).count()
    return render_template('admin_dashboard.html', 
                         suggestions=suggestions,
                         today_count=today_count)

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add_admin():
    if not current_user.is_superadmin:
        flash('Only superadmins can add admins', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_superadmin = bool(request.form.get('is_superadmin'))

        if Admin.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            new_admin = Admin(
                username=username,
                is_superadmin=is_superadmin,
                created_by=current_user.id
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin account created successfully', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin/create_admin.html')

@app.route('/admin/remove/<int:admin_id>', methods=['POST'])
@login_required
def remove_admin(admin_id):
    if not current_user.is_superadmin:
        flash('Only superadmins can remove admins', 'error')
        return redirect(url_for('admin_dashboard'))

    admin_to_remove = Admin.query.get(admin_id)
    if not admin_to_remove:
        flash('Admin not found', 'error')
    elif admin_to_remove.id == current_user.id:
        flash('You cannot remove yourself', 'error')
    else:
        db.session.delete(admin_to_remove)
        db.session.commit()
        flash('Admin removed successfully', 'success')

    return redirect(url_for('admin_dashboard'))

# Initial setup
def create_tables():
    with app.app_context():
        db.create_all()

def create_admin():
    with app.app_context():
        if not Admin.query.first():
            admin = Admin(
                username='admin',
                is_superadmin=True  # Make first admin a superadmin
            )
            admin.set_password('admin123')  # Change in production!
            db.session.add(admin)
            db.session.commit()
            print("Superadmin created. Username: admin, Password: admin123")
def initialize_database():
    with app.app_context():
        # Check if tables exist
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'admin' not in tables:
            db.create_all()
            create_admin()
        else:
            # Handle existing database
            from sqlalchemy import text
            try:
                # Check if columns exist
                db.session.execute(text('SELECT is_superadmin FROM admin LIMIT 1'))
            except:
                # If columns don't exist, migrate manually
                db.session.execute(text('ALTER TABLE admin ADD COLUMN is_superadmin BOOLEAN DEFAULT FALSE'))
                db.session.execute(text('ALTER TABLE admin ADD COLUMN created_by INTEGER'))
                db.session.commit()
                
                # Set first admin as superadmin
                admin = Admin.query.first()
                if admin:
                    admin.is_superadmin = True
                    db.session.commit()

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)
