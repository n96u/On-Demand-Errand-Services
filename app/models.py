from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(db.Model):
    """User model for clients, runners, and admins"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # client, runner, admin
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    barangay = db.Column(db.String(100))
    address = db.Column(db.Text)
    bio = db.Column(db.Text)
    vehicle_type = db.Column(db.String(50))
    available_hours = db.Column(db.String(100))
    verified = db.Column(db.Boolean, default=False)
    verification_requested = db.Column(db.Boolean, default=False)
    verification_status = db.Column(db.String(20), default='not_requested')
    last_verification_date = db.Column(db.DateTime)
    rejection_reason = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    wallet_balance = db.Column(db.Float, default=0.0)
    total_earnings = db.Column(db.Float, default=0.0)
    total_spent = db.Column(db.Float, default=0.0)
    average_rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)

    # Relationships - using unique backref names
    received_ratings = db.relationship('Rating', foreign_keys='Rating.runner_id', backref='rated_runner', lazy=True)
    given_ratings = db.relationship('Rating', foreign_keys='Rating.client_id', backref='rating_author', lazy=True)

    # Relationships - using unique backref names
    created_errands = db.relationship('Errand', foreign_keys='Errand.client_id', backref='user_client', lazy=True)
    accepted_errands = db.relationship('Errand', foreign_keys='Errand.runner_id', backref='user_runner', lazy=True)
    
    # Payment relationships
    client_payments = db.relationship('Payment', foreign_keys='Payment.client_id', backref='payment_client_user', lazy=True)
    runner_payments = db.relationship('Payment', foreign_keys='Payment.runner_id', backref='payment_runner_user', lazy=True)
    
    # Wallet relationships
    wallet_transactions = db.relationship('WalletTransaction', backref='transaction_user', lazy=True)
    user_payment_methods = db.relationship('PaymentMethod', backref='method_owner', lazy=True)
    user_wallet = db.relationship('Wallet', backref='wallet_owner_user', uselist=False)

    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Errand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    pickup_address = db.Column(db.String(200), nullable=False)
    dropoff_address = db.Column(db.String(200), nullable=False)
    barangay = db.Column(db.String(100), nullable=False)
    preferred_time = db.Column(db.DateTime)
    proposed_fee = db.Column(db.Float, nullable=False)
    final_fee = db.Column(db.Float)
    status = db.Column(db.String(20), default='Pending')
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    runner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    payment_id = db.Column(db.Integer, db.ForeignKey('payment.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    accepted_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Add this relationship to access the Payment object
    payment = db.relationship('Payment', backref='errand_payment', foreign_keys=[payment_id])
    
    def __repr__(self):
        return f'<Errand {self.id} - {self.category}>'


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='user_notifications')


class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)


class Wallet(db.Model):
    """User wallet for storing balance"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transactions = db.relationship('WalletTransaction', backref='transaction_wallet', lazy=True)
    
    def __repr__(self):
        return f'<Wallet {self.id}: ₱{self.balance:.2f}>'


class WalletTransaction(db.Model):
    """Wallet transaction history"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # deposit, withdrawal, payment, refund, earnings
    amount = db.Column(db.Float, nullable=False)
    balance_before = db.Column(db.Float, nullable=False)
    balance_after = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    reference_id = db.Column(db.String(100))  # payment_id, errand_id, or external reference
    status = db.Column(db.String(20), default='completed')  # pending, completed, failed, refunded
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<WalletTransaction {self.id}: {self.transaction_type} ₱{self.amount:.2f}>'


class PaymentMethod(db.Model):
    """User's saved payment methods"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    method_type = db.Column(db.String(50), nullable=False)  # gcash, paymaya, bank, card
    provider = db.Column(db.String(100))  # BPI, GCash, PayMaya, etc.
    account_name = db.Column(db.String(200))
    account_number = db.Column(db.String(100))
    is_default = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PaymentMethod {self.method_type}: {self.account_number}>'


class Payment(db.Model):
    """Payment transactions for errands"""
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)
    errand_id = db.Column(db.Integer, db.ForeignKey('errand.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    runner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float, nullable=False)
    platform_fee = db.Column(db.Float, nullable=False)
    vat_amount = db.Column(db.Float, nullable=False)
    runner_earnings = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    released_at = db.Column(db.DateTime)
    refunded_at = db.Column(db.DateTime)
    
    # Add these relationships
    errand = db.relationship('Errand', backref='payment_errand', foreign_keys=[errand_id])
    client = db.relationship('User', foreign_keys=[client_id])
    runner = db.relationship('User', foreign_keys=[runner_id])
    
    def __repr__(self):
        return f'<Payment {self.transaction_id}: ₱{self.amount:.2f}>'
    
class PasswordResetToken(db.Model):
    """Password reset token model"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(200), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='reset_tokens')
    
    def is_valid(self):
        """Check if token is still valid"""
        return not self.used and self.expires_at > datetime.utcnow()
    
    def __repr__(self):
        return f'<PasswordResetToken {self.token[:10]}...>'
    
class Rating(db.Model):
    """Ratings and feedback for completed errands"""
    id = db.Column(db.Integer, primary_key=True)
    errand_id = db.Column(db.Integer, db.ForeignKey('errand.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    runner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # 1 to 5 stars
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    errand = db.relationship('Errand', backref=db.backref('rating', uselist=False))
    
    def __repr__(self):
        return f'<Rating {self.score} stars for Errand #{self.errand_id}>'
    

