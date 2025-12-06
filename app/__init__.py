from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
import os

db = SQLAlchemy()
migrate = Migrate()
session_store = Session()  # Add this

from app import models

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///grabitdone.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Session configuration for multiple users
    app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on disk
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_COOKIE_NAME'] = 'grabitdone_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_FILE_DIR'] = './flask_session'  # Directory for session files
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    session_store.init_app(app)  # Initialize session
    
    # Register blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Initialize database within app context
    with app.app_context():
        initialize_database()
    
    return app

def initialize_database():
    """Initialize database with admin and default config"""
    # Create all tables
    db.create_all()
    
    # Check for admin user
    from app.models import User, SystemConfig, Wallet
    
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@grabitdone.com',
            role='admin',
            first_name='System',
            last_name='Administrator',
            phone='123-456-7890',
            barangay='Barangay 1',
            verified=True,
            verification_status='approved',
            is_active=True,
            wallet_balance=0.0
        )
        admin_user.set_password('admin')
        db.session.add(admin_user)
        
        try:
            db.session.commit()
            print("✓ Admin user created: admin / admin")
            
        except Exception as e:
            db.session.rollback()
            print(f"✗ Error creating admin user: {e}")
            return
    
    # CREATE WALLETS FOR ALL EXISTING USERS
    all_users = User.query.all()
    for user in all_users:
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        if not wallet:
            wallet = Wallet(user_id=user.id, balance=user.wallet_balance or 0.0)
            db.session.add(wallet)
            print(f"✓ Created wallet for user: {user.username}")
    
    # Add default configuration
    default_configs = {
        'foodDeliveryFee': '100.00',
        'groceryFee': '150.00',
        'packageFee': '80.00',
        'documentFee': '120.00',
        'otherErrandFee': '100.00',
        'minServiceFee': '50.00',
        'platformCommission': '10.00',
        'vatRate': '12.00',
        'baseDeliveryFee': '50.00',
        'perKmRate': '15.00',
        'maxDistance': '20',
        'barangay1Distance': '2.5',
        'barangay2Distance': '5.0',
        'barangay3Distance': '7.5',
        'barangay4Distance': '10.0',
        'barangay5Distance': '12.5',
        'defaultDistance': '5.0',
    }
    
    for key, value in default_configs.items():
        if not SystemConfig.query.filter_by(key=key).first():
            config = SystemConfig(key=key, value=value)
            db.session.add(config)
            print(f"✓ Added system config: {key} = {value}")
    
    try:
        db.session.commit()
        print("✓ Database initialized successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"✗ Database initialization error: {e}")