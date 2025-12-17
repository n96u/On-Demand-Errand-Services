from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import os
from app import db
import hashlib
import uuid
from app.models import User, Errand, Notification, SystemConfig, Wallet, WalletTransaction, Payment, PaymentMethod
from app.wallet import (calculate_fees, create_wallet_transaction, 
                        process_errand_payment, process_refund, generate_transaction_id)
from app.password_reset import (create_password_reset_token, send_password_reset_email, 
                                validate_reset_token, mark_token_used)



bp = Blueprint('main', __name__)

# ===== CONSTANTS =====
BARANGAYS = ['Barangay 1', 'Barangay 2', 'Barangay 3', 'Barangay 4', 'Barangay 5']


# ===== HELPER FUNCTIONS =====
def validate_session():
    """Validate if current session matches the user"""
    if 'user_id' not in session:
        return False
    
    # Get session ID from session and cookie
    session_hash = session.get('session_id')
    cookie_session = request.cookies.get('user_session')
    
    if not session_hash or not cookie_session:
        return False
    
    # Check if session matches cookie
    expected_cookie = f"{session['user_id']}_{session_hash}"
    return cookie_session == expected_cookie

def login_required(role=None):
    """Decorator to check if user is logged in and has required role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('main.login'))
            
            # Validate session
            if not validate_session():
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('main.login'))
            
            user = User.query.get(session['user_id'])
            if not user:
                flash('User not found. Please log in again.', 'error')
                session.clear()
                return redirect(url_for('main.login'))
            
            if not user.is_active and request.endpoint != 'main.account_suspended':
                return redirect(url_for('main.account_suspended'))
            
            if role and user.role != role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('main.dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Access denied. Administrator privileges required.', 'error')
            
            if request.is_json or 'application/json' in request.accept_mimetypes:
                return jsonify({'error': 'Access denied. Administrator privileges required.'}), 403
            
            return redirect(url_for('main.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function


def create_notification(user_id, message):
    """Helper function to create notifications"""
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()

def has_pending_refund_request(user_id, errand_id):
    """Check if user already has a pending refund request for this errand"""
    existing = WalletTransaction.query.filter(
        WalletTransaction.user_id == user_id,
        WalletTransaction.transaction_type.in_(['refund_request', 'refund']),
        WalletTransaction.status == 'pending',
        WalletTransaction.description.like(f'%errand #{errand_id}%')
    ).first()
    return existing is not None


def get_errand_refund_status(errand_id):
    """Check if errand has pending or rejected refund request"""
    refund_request = WalletTransaction.query.filter(
        WalletTransaction.transaction_type.in_(['refund_request', 'refund']),
        WalletTransaction.description.like(f'%errand #{errand_id}%')
    ).order_by(WalletTransaction.created_at.desc()).first()
    
    if refund_request:
        if refund_request.status == 'pending':
            return 'refund_pending'
        elif refund_request.status == 'rejected':
            return 'refund_rejected'
        elif refund_request.status == 'completed':
            return 'refunded'
    
    return None

def get_errand_display_status(errand):
    """Get the display status for an errand, considering refund status"""
    if errand.status == 'Completed':
        refund_status = get_errand_refund_status(errand.id)
        if refund_status == 'refunded':
            return 'Refunded'
        elif refund_status == 'refund_pending':
            return 'Refund Pending'
        elif refund_status == 'refund_rejected':
            return 'Refund Rejected'
    
    return errand.status  # Return original status for all other cases
    
def get_upload_path(user_id, filename=None):
    """Get the correct upload path for verification documents"""
    # Get app directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to project root
    project_root = os.path.dirname(app_dir)
    
    if filename:
        return os.path.join(project_root, 'uploads', 'verification_docs', str(user_id), filename)
    else:
        return os.path.join(project_root, 'uploads', 'verification_docs', str(user_id))

# ===== CONTEXT PROCESSORS =====
@bp.context_processor
def inject_notifications():
    user_data = {
        'notifications': [],
        'unread_notification_count': 0,
        'user_verified': False,
        'user_role': None,
        'verification_status': 'not_requested'
    }
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            notifications = Notification.query.filter_by(
                user_id=session['user_id']
            ).order_by(Notification.created_at.desc()).all()
            unread_count = Notification.query.filter_by(
                user_id=session['user_id'],
                is_read=False
            ).count()
            
            user_data = {
                'notifications': notifications,
                'unread_notification_count': unread_count,
                'user_verified': user.verified,
                'user_role': user.role,
                'verification_status': user.verification_status
            }
    
    return user_data

@bp.context_processor
def utility_processor():
    import time
    from datetime import datetime as dt
    import os
    from werkzeug.utils import secure_filename
    
    def get_user_verification_documents(user_id):
        """Get all verification documents for a user from the file system"""
        user_folder = os.path.join('uploads', 'verification_docs', str(user_id))
        
        if not os.path.exists(user_folder):
            return []
        
        documents = []
        
        try:
            for filename in os.listdir(user_folder):
                file_path = os.path.join(user_folder, filename)
                
                if os.path.isfile(file_path):
                    if filename.startswith('.'):
                        continue
                    
                    file_size = os.path.getsize(file_path)
                    upload_time = os.path.getmtime(file_path)
                    
                    doc_type = 'other'
                    if filename.startswith('government_id'):
                        doc_type = 'government_id'
                    elif filename.startswith('drivers_license'):
                        doc_type = 'drivers_license'
                    elif filename.startswith('vehicle_registration'):
                        doc_type = 'vehicle_registration'
                    elif filename.startswith('insurance'):
                        doc_type = 'insurance'
                    elif filename.startswith('proof_of_address'):
                        doc_type = 'proof_of_address'
                    
                    parts = filename.split('_')
                    if len(parts) >= 3:
                        original_name = '_'.join(parts[2:])
                    else:
                        original_name = filename
                    
                    documents.append({
                        'filename': filename,
                        'original_name': original_name,
                        'file_path': file_path,
                        'document_type': doc_type,
                        'file_size': file_size,
                        'uploaded_time': upload_time
                    })
                    
        except Exception as e:
            print(f"Error reading documents for user {user_id}: {e}")
        
        return documents
    
    def timestamp_to_date(timestamp):
        """Convert timestamp to readable date"""
        try:
            return dt.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
        except:
            return 'Unknown'
    
    return dict(
        get_user_verification_documents=get_user_verification_documents,
        timestamp_to_date=timestamp_to_date,
        get_errand_refund_status=get_errand_refund_status,
        get_errand_display_status=get_errand_display_status 
    )

# ===== BASIC ROUTES =====
@bp.route('/')
def index():
    """Home page - public access"""
    return render_template('index.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                session['user_id'] = user.id
                session['user_role'] = user.role
                session['username'] = user.username
                flash('Your account has been suspended.', 'error')
                return redirect(url_for('main.account_suspended'))
            
            # Generate unique session identifier based on user agent
            user_agent = request.headers.get('User-Agent', '')
            ip_address = request.remote_addr
            session_hash = hashlib.sha256(
                f"{user.id}_{user_agent}_{ip_address}".encode()
            ).hexdigest()[:16]
            
            # Store in session
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['username'] = user.username
            session['session_id'] = session_hash  # Add unique session ID
            
            # Also store in user's browser as a cookie for tab management
            response = redirect(url_for('main.dashboard'))
            response.set_cookie('user_session', f"{user.id}_{session_hash}", max_age=3600*24*7)  # 7 days
            
            flash('Login successful!', 'success')
            return response
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']
        barangay = request.form['barangay']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('main.register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('main.register'))
        
        new_user = User(
            username=username,
            email=email,
            role=role,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            barangay=barangay,
            verified=True if role == 'admin' else False,
            verification_status='approved' if role == 'admin' else 'not_requested'
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        if role == 'runner':
            create_notification(new_user.id, 'Complete your account verification to start accepting errands.')
        elif role == 'client':
            create_notification(new_user.id, 'Complete your account verification to start posting errands.')
        else:
            create_notification(new_user.id, 'Welcome as an administrator! Your account is already verified.')
        
        flash('Registration successful!', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('auth/register.html', barangays=BARANGAYS)

@bp.route('/logout')
def logout():
    """User logout"""
    # Clear server-side session
    session.clear()
    
    # Create response that clears cookies
    response = redirect(url_for('main.index'))
    response.delete_cookie('user_session')
    
    flash('You have been logged out.', 'success')
    return response

# ===== DASHBOARD ROUTES =====
@bp.route('/dashboard')
@login_required()
def dashboard():
    """Main dashboard - role-based view"""
    user = User.query.get(session['user_id'])
    
    if not user.is_active:
        return redirect(url_for('main.account_suspended'))
    
    if user.role == 'client':
        return client_dashboard(user)
    elif user.role == 'runner':
        return runner_dashboard(user)
    elif user.role == 'admin':
        return admin_dashboard(user)

def client_dashboard(user):
    """Client-specific dashboard"""
    # Check if user is verified
    if not user.verified and user.verification_status != 'approved':
        # Show limited dashboard with verification prompt
        return render_template('shared/dashboard_unverified.html', 
                             user=user)
    
    active_errands = Errand.query.filter_by(
        client_id=session['user_id']
    ).filter(
        Errand.status.in_(['Pending', 'Accepted', 'In Progress'])
    ).all()
    
    completed_errands = Errand.query.filter_by(
        client_id=session['user_id'],
        status='Completed'
    ).all()
    
    return render_template('client/dashboard_client.html', 
                        user=user,
                        active_errands=active_errands,
                        completed_errands=completed_errands)


def runner_dashboard(user):
    """Runner-specific dashboard"""
    # Check if user is verified
    if not user.verified and user.verification_status != 'approved':
        # Show limited dashboard with verification prompt
        return render_template('shared/dashboard_unverified.html', 
                             user=user)
    
    available_errands = Errand.query.filter_by(status='Pending').all()
    accepted_errands = Errand.query.filter_by(runner_id=session['user_id']).all()
    
    completed_errands = [e for e in accepted_errands if e.status == 'Completed']
    total_earnings = sum(e.final_fee or e.proposed_fee for e in completed_errands)
    weekly_earnings = total_earnings * 0.2
    
    return render_template('runner/dashboard_runner.html', 
                         user=user,
                         available_errands=available_errands,
                         accepted_errands=accepted_errands,
                         total_earnings=total_earnings,
                         weekly_earnings=weekly_earnings,
                         completed_count=len(completed_errands))


def admin_dashboard(user):
    """Admin-specific dashboard"""
    total_users = User.query.count()
    total_errands = Errand.query.count()
    active_errands = Errand.query.filter(Errand.status.in_(['Pending', 'Accepted', 'In Progress'])).count()
    today_errands = Errand.query.filter(Errand.created_at >= datetime.today().date()).count()
    
    users = User.query.all()
    errands = Errand.query.all()
    
    return render_template('admin/dashboard_admin.html',
                         user=user,
                         total_users=total_users,
                         total_errands=total_errands,
                         active_errands=active_errands,
                         today_errands=today_errands,
                         users=users,
                         errands=errands)

# ===== CLIENT ROUTES =====
@bp.route('/create-errand', methods=['GET', 'POST'])
@login_required('client')
def create_errand():
    """Create new errand - client only with payment integration"""
    user = User.query.get(session['user_id'])
    
    if not user:
        flash('User not found. Please log in again.', 'error')
        session.clear()
        return redirect(url_for('main.login'))
    
    # --- GLOBAL VERIFICATION WALL ---
    # If not verified, stop here and show the unverified wall immediately
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    # Load all system configuration
    configs = SystemConfig.query.all()
    config_dict = {config.key: config.value for config in configs}
    
    # Load categories with prices from system config
    categories = {}
    category_mapping = {
        'foodDeliveryFee': 'Food Delivery',
        'groceryFee': 'Grocery Shopping',
        'packageFee': 'Package Pickup',
        'documentFee': 'Document Processing',
        'otherErrandFee': 'Other Errands'
    }
    
    # Convert config values to float for calculations
    config_floats = {}
    for key, value in config_dict.items():
        try:
            config_floats[key] = float(value)
        except (ValueError, TypeError):
            # Use defaults if conversion fails
            defaults = {
                'foodDeliveryFee': 100.00,
                'groceryFee': 150.00,
                'packageFee': 80.00,
                'documentFee': 120.00,
                'otherErrandFee': 100.00,
                'minServiceFee': 50.00,
                'platformCommission': 10.00,
                'vatRate': 12.00,
                'baseDeliveryFee': 50.00,
                'perKmRate': 15.00,
                'maxDistance': 20.0,
                'barangay1Distance': 2.5,
                'barangay2Distance': 5.0,
                'barangay3Distance': 7.5,
                'barangay4Distance': 10.0,
                'barangay5Distance': 12.5,
                'defaultDistance': 5.0,
            }
            config_floats[key] = defaults.get(key, 0.0)
    
    for key, category_name in category_mapping.items():
        categories[category_name] = config_floats.get(key, 100.00)
    
    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']
        pickup_address = request.form['pickup_address']
        dropoff_address = request.form['dropoff_address']
        barangay = request.form['barangay']
        preferred_time = request.form.get('preferred_time')
        payment_method = request.form.get('payment_method', 'wallet')
        use_wallet = request.form.get('use_wallet') == 'on'
        
        # Get base price from categories
        base_price = categories.get(category, 100.00)
        
        # Calculate distance-based delivery fee
        distance_key = f"{barangay.lower().replace(' ', '')}Distance"
        distance = config_floats.get(distance_key, config_floats.get('defaultDistance', 5.0))
        
        # Calculate fees
        base_delivery_fee = config_floats.get('baseDeliveryFee', 50.00)
        per_km_rate = config_floats.get('perKmRate', 15.00)
        delivery_fee = base_delivery_fee + (distance * per_km_rate)
        
        # Calculate subtotal
        subtotal = base_price + delivery_fee
        
        # Calculate tax (VAT)
        vat_rate = config_floats.get('vatRate', 12.00) / 100
        vat_amount = subtotal * vat_rate
        
        # Calculate platform commission
        platform_commission_rate = config_floats.get('platformCommission', 10.00) / 100
        platform_fee = subtotal * platform_commission_rate
        
        # Calculate total amount (what client pays)
        total_amount = subtotal + vat_amount
        
        # Calculate runner earnings
        runner_earnings = subtotal - platform_fee
        
        # Check wallet balance if using wallet
        if use_wallet and user.wallet_balance < total_amount:
            flash(f'Insufficient wallet balance (₱{user.wallet_balance:.2f}). You need ₱{total_amount:.2f}. Please add funds or use another payment method.', 'error')
            return redirect(url_for('main.create_errand'))
        
        if preferred_time:
            try:
                preferred_time = datetime.fromisoformat(preferred_time)
            except:
                preferred_time = None
        
        # Create errand
        new_errand = Errand(
            category=category,
            description=description,
            pickup_address=pickup_address,
            dropoff_address=dropoff_address,
            barangay=barangay,
            preferred_time=preferred_time,
            proposed_fee=base_price,
            final_fee=total_amount,
            client_id=session['user_id'],
            status='Pending'
        )
        
        db.session.add(new_errand)
        db.session.flush()  # Get errand ID
        
        # Create payment record
        transaction_id = generate_transaction_id()
        payment = Payment(
            transaction_id=transaction_id,
            errand_id=new_errand.id,
            client_id=session['user_id'],
            runner_id=None,  # Will be set when runner accepts
            amount=base_price,
            platform_fee=platform_fee,
            vat_amount=vat_amount,
            runner_earnings=runner_earnings,
            payment_method=payment_method,
            payment_status='prepaid'
        )
        
        db.session.add(payment)
        db.session.flush()
        
        # Link payment to errand
        new_errand.payment_id = payment.id
        
        # Process wallet payment if using wallet
        if use_wallet:
            from app.wallet import create_wallet_transacztion
            success, message = create_wallet_transaction(
                user_id=session['user_id'],
                transaction_type='payment',
                amount=-total_amount,  # Negative for payment
                description=f'Payment for errand #{new_errand.id} - {category}',
                reference_id=transaction_id
            )
            
            if not success:
                db.session.rollback()
                flash(f'Payment failed: {message}', 'error')
                return redirect(url_for('main.create_errand'))
            
            # Update user wallet balance
            user.wallet_balance -= total_amount
            wallet = Wallet.query.filter_by(user_id=user.id).first()
            if wallet:
                wallet.balance = user.wallet_balance
            
            payment.paid_at = datetime.utcnow()
        
        db.session.commit()
        
        # Create notifications
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.id, f'New errand created: {category} in {barangay} for ₱{total_amount:.2f}')
        
        create_notification(user.id, f'Errand #{new_errand.id} created successfully! Payment of ₱{total_amount:.2f} processed.')
        
        flash(f'Errand created and paid successfully! Total: ₱{total_amount:.2f}', 'success')
        return redirect(url_for('main.active_errands'))
    
    # Prepare config for template (convert float values to strings for JSON serialization)
    config_for_template = {}
    for key, value in config_floats.items():
        config_for_template[key] = value
    
    return render_template('client/create_errand.html', 
                        user=user,
                        categories=categories,
                        config=config_for_template,
                        barangays=BARANGAYS)

# ===== UPDATE ACCEPT ERRAND ROUTE =====
@bp.route('/accept-errand/<int:errand_id>')
@login_required('runner')
def accept_errand(errand_id):
    # Get the current user
    user = User.query.get(session['user_id'])
    
    # Check if user is verified
    if not user.verified and user.verification_status != 'approved':
        flash('You need to verify your account before accepting errands.', 'error')
        return redirect(url_for('main.verification'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    if errand.status != 'Pending':
        flash('This errand is no longer available.', 'error')
        return redirect(url_for('main.available_errands_runner'))
    
    # Check if errand has payment
    payment = Payment.query.get(errand.payment_id) if errand.payment_id else None
    if not payment:
        flash('This errand has no payment associated.', 'error')
        return redirect(url_for('main.available_errands_runner'))
    
    # Calculate runner earnings
    from app.wallet import calculate_fees
    fees = calculate_fees(errand.proposed_fee)
    
    # Update errand with runner info
    errand.runner_id = session['user_id']
    errand.status = 'Accepted'
    errand.accepted_at = datetime.utcnow()
    
    # Update payment with runner info
    payment.runner_id = session['user_id']
    
    # Create notifications
    create_notification(errand.client_id, 
                       f'Your errand #{errand.id} has been accepted by a runner!')
    create_notification(session['user_id'],
                       f'You accepted errand #{errand.id}. You will earn ₱{fees["runner_earnings"]:.2f} upon completion.')
    
    db.session.commit()
    flash(f'Errand accepted! You will earn ₱{fees["runner_earnings"]:.2f} upon completion.', 'success')
    return redirect(url_for('main.my_errands_runner'))


@bp.route('/complete-errand/<int:errand_id>')
@login_required()
def complete_errand(errand_id):
    """Complete errand and automatically release payment to runner"""
    user = User.query.get(session['user_id'])
    
    # If user is a runner, check verification
    if user.role == 'runner' and (not user.verified and user.verification_status != 'approved'):
        flash('You need to verify your account before completing errands.', 'error')
        return redirect(url_for('main.verification'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check permissions
    if user.role == 'runner' and errand.runner_id != user.id:
        flash('You can only complete your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if user.role == 'client' and errand.client_id != user.id:
        flash('You can only complete your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Check if errand can be completed
    if errand.status not in ['Accepted', 'In Progress']:
        flash('This errand cannot be completed.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Update errand status
    errand.status = 'Completed'
    errand.completed_at = datetime.utcnow()
    
    # Initialize payment variable
    payment = None
    runner_earnings = 0.0
    
    # AUTO-RELEASE PAYMENT TO RUNNER
    if errand.payment_id and errand.runner_id:
        payment = Payment.query.get(errand.payment_id)
        if payment and payment.payment_status == 'prepaid':
            from app.wallet import auto_release_payment_to_runner
            success, message = auto_release_payment_to_runner(payment.id)
            
            if success:
                runner_earnings = payment.runner_earnings
                flash(f'Errand completed! ₱{runner_earnings:.2f} has been automatically added to your wallet.', 'success')
            else:
                flash(f'Errand completed but payment release failed: {message}. Contact admin.', 'warning')
    
    # Create notifications
    create_notification(errand.client_id,
                       f'Your errand #{errand.id} has been completed!')
    
    if errand.runner_id:
        # FIXED: Use proper string formatting
        notification_message = f'Errand #{errand.id} marked as completed.'
        if payment and payment.payment_status == 'released':
            notification_message += f' ₱{payment.runner_earnings:.2f} automatically added to your wallet!'
        
        create_notification(errand.runner_id, notification_message)
    
    db.session.commit()
    
    # Redirect based on role
    if user.role == 'runner':
        return redirect(url_for('main.my_errands_runner'))
    else:
        return redirect(url_for('main.dashboard'))


@bp.route('/active-errands')
@login_required('client')
def active_errands():
    """View active errands - client only"""
    user = User.query.get(session['user_id'])
    
    # --- GLOBAL VERIFICATION WALL ---
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    active_errands = Errand.query.filter_by(
        client_id=session['user_id']
    ).filter(
        Errand.status.in_(['Pending', 'Accepted', 'In Progress'])
    ).order_by(Errand.created_at.desc()).all()
    
    return render_template('shared/active_errands.html', 
                        user=user,
                        active_errands=active_errands)


@bp.route('/errand_history')
@login_required('client')
def errand_history():
    """View errand history - client only"""
    user = User.query.get(session['user_id'])
    
    # --- GLOBAL VERIFICATION WALL ---
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    completed_errands = Errand.query.filter_by(
        client_id=session['user_id'],
        status='Completed'
    ).order_by(Errand.completed_at.desc()).all()
    
    canceled_errands = Errand.query.filter_by(
        client_id=session['user_id'],
        status='Canceled'
    ).order_by(Errand.created_at.desc()).all()
    
    # Get refund status for each errand
    refunded_errands = []
    refund_pending_errands = []
    refund_rejected_errands = []
    true_completed_errands = []
    
    for errand in completed_errands:
        refund_status = get_errand_refund_status(errand.id)
        
        if refund_status == 'refunded':
            refunded_errands.append(errand)
        elif refund_status == 'refund_pending':
            refund_pending_errands.append(errand)
        elif refund_status == 'refund_rejected':
            refund_rejected_errands.append(errand)
        else:
            true_completed_errands.append(errand)
    
    total_spent = sum((e.final_fee or e.proposed_fee) for e in completed_errands if (e.final_fee or e.proposed_fee) is not None)
    
    return render_template('client/errand_history.html', 
                        user=user,
                        completed_errands=true_completed_errands,
                        refunded_errands=refunded_errands,
                        refund_pending_errands=refund_pending_errands,
                        refund_rejected_errands=refund_rejected_errands,
                        canceled_errands=canceled_errands,
                        total_spent=total_spent)


# ===== RUNNER ROUTES =====
@bp.route('/available-errands-runner')
@login_required('runner')
def available_errands_runner():
    """View available errands - runner only"""
    user = User.query.get(session['user_id'])
    
    # --- GLOBAL VERIFICATION WALL ---
    # If not verified, stop here and show the unverified wall immediately
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    available_errands = Errand.query.filter_by(status='Pending').order_by(Errand.created_at.desc()).all()
    
    return render_template('runner/available_errands_runner.html', 
                        user=user,
                        available_errands=available_errands)


@bp.route('/my-errands-runner')
@login_required('runner')
def my_errands_runner():
    """View accepted errands - runner only"""
    user = User.query.get(session['user_id'])
    
    # --- GLOBAL VERIFICATION WALL ---
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    accepted_errands = Errand.query.filter_by(runner_id=session['user_id']).order_by(Errand.created_at.desc()).all()
    
    return render_template('runner/my_errands_runner.html', 
                        user=user,
                        accepted_errands=accepted_errands)

@bp.route('/earnings-runner')
@login_required('runner')
def earnings_runner():
    """View earnings - runner only"""
    user = User.query.get(session['user_id'])
    
    # Check if user is verified
    if not user.verified and user.verification_status != 'approved':
        return render_template('shared/dashboard_unverified.html', user=user)
    
    accepted_errands = Errand.query.filter_by(runner_id=session['user_id']).all()
    
    completed_errands = [e for e in accepted_errands if e.status == 'Completed']
    total_earnings = sum(e.final_fee or e.proposed_fee for e in completed_errands)
    weekly_earnings = total_earnings * 0.2
    average_earning = total_earnings / len(completed_errands) if completed_errands else 0
    
    return render_template('runner/earnings_runner.html', 
                        user=user,
                        accepted_errands=accepted_errands,
                        total_earnings=total_earnings,
                        weekly_earnings=weekly_earnings,
                        completed_count=len(completed_errands),
                        average_earning=average_earning)

@bp.route('/runner/errand-history')
@login_required('runner')
def runner_errand_history():
    """View runner errand history - runner only"""
    user = User.query.get(session['user_id'])
    
    # Check if user is verified
    if not user.verified and user.verification_status != 'approved':
        flash('You need to verify your account to view errand history.', 'error')
        return redirect(url_for('main.verification'))
    
    all_errands = Errand.query.filter_by(runner_id=session['user_id']).order_by(Errand.created_at.desc()).all()
    
    completed_errands = [e for e in all_errands if e.status == 'Completed']
    in_progress_errands = [e for e in all_errands if e.status in ['Accepted', 'In Progress']]
    canceled_errands = [e for e in all_errands if e.status == 'Canceled']
    
    total_earnings = sum(e.final_fee or e.proposed_fee for e in completed_errands)
    
    return render_template('runner/errand_history.html', 
                        user=user,
                        all_errands=all_errands,
                        completed_errands=completed_errands,
                        in_progress_errands=in_progress_errands,
                        canceled_errands=canceled_errands,
                        total_earnings=total_earnings)

# ===== SHARED ROUTES =====
@bp.route('/profile', methods=['GET', 'POST'])
@login_required()
def profile():
    """User profile management - all roles"""
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']
        user.phone = request.form['phone']
        user.barangay = request.form['barangay']
        user.address = request.form.get('address', '')
        
        if user.role == 'runner':
            user.bio = request.form.get('bio', '')
            user.vehicle_type = request.form.get('vehicle_type', '')
            user.available_hours = request.form.get('available_hours', '')
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('main.profile'))
    
    return render_template('shared/profile.html', user=user, barangays=BARANGAYS)


@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request page"""
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Please enter your email address.', 'error')
            return redirect(url_for('main.forgot_password'))
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Create reset token
            token = create_password_reset_token(user.id)
            
            # Send reset email
            success, message = send_password_reset_email(user, token)
            
            if success:
                flash('Password reset instructions have been sent to your email.', 'success')
            else:
                flash(f'Error: {message}', 'error')
        else:
            # Don't reveal if email exists (security best practice)
            flash('If an account exists with this email, you will receive password reset instructions.', 'info')
        
        return redirect(url_for('main.login'))
    
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    # Validate token
    user, error_message = validate_reset_token(token)
    
    if not user:
        flash(error_message or 'Invalid or expired reset link.', 'error')
        return redirect(url_for('main.forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords
        if not password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('main.reset_password', token=token))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('main.reset_password', token=token))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('main.reset_password', token=token))
        
        # Update password
        user.set_password(password)
        
        # Mark token as used
        mark_token_used(token)
        
        db.session.commit()
        
        # Create notification
        create_notification(user.id, 'Your password has been successfully reset.')
        
        flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('auth/reset_password.html', token=token, user=user)


@bp.route('/change-password', methods=['POST'])
@login_required()
def change_password():
    """Change password for logged-in users"""
    user = User.query.get(session['user_id'])
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validation
    errors = []
    
    if not current_password:
        errors.append('Current password is required.')
    
    if not new_password:
        errors.append('New password is required.')
    elif len(new_password) < 6:
        errors.append('Password must be at least 6 characters long.')
    
    if not confirm_password:
        errors.append('Please confirm your new password.')
    elif new_password != confirm_password:
        errors.append('New passwords do not match.')
    
    if errors:
        for error in errors:
            flash(error, 'error')
        return redirect(url_for('main.profile'))
    
    # Check current password
    if not user.check_password(current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('main.profile'))
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    # Create notification
    create_notification(user.id, 'Your password has been changed successfully.')
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('main.profile'))


# ===== NOTIFICATION ROUTES =====
@bp.route('/notifications')
@login_required()
def notifications():
    """View user notifications - all roles"""
    user_notifications = Notification.query.filter_by(
        user_id=session['user_id']
    ).order_by(Notification.created_at.desc()).all()
    
    return render_template('shared/notifications.html', notifications=user_notifications)

@bp.route('/mark-all-read')
@login_required()
def mark_all_read():
    """Mark all notifications as read - all roles"""
    unread_notifications = Notification.query.filter_by(
        user_id=session['user_id'],
        is_read=False
    ).all()
    
    for notification in unread_notifications:
        notification.is_read = True
    
    db.session.commit()
    
    flash('All notifications marked as read!', 'success')
    return redirect(url_for('main.notifications'))

@bp.route('/mark-notification-read/<int:notification_id>')
@login_required()
def mark_notification_read(notification_id):
    """Mark notification as read - all roles"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != session['user_id']:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('main.notifications'))
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(url_for('main.notifications'))

# ===== ERRAND MANAGEMENT ROUTES =====
@bp.route('/view-errand/<int:errand_id>')
@login_required()
def view_errand(errand_id):
    user = User.query.get(session['user_id'])
    errand = Errand.query.get_or_404(errand_id)
    
    if user.role == 'runner' and errand.runner_id != user.id and errand.status == 'Pending':
        if not user.verified and user.verification_status != 'approved':
            flash('You need to verify your account to view available errands.', 'error')
            return redirect(url_for('main.verification'))
    
    if user.role == 'client' and errand.client_id != user.id:
        flash('You can only view your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if user.role == 'runner' and errand.runner_id != user.id and errand.status != 'Pending':
        flash('You can only view errands you accepted.', 'error')
        return redirect(url_for('main.dashboard'))
    
    client = User.query.get(errand.client_id)
    runner = User.query.get(errand.runner_id) if errand.runner_id else None

    # Get refund status
    refund_status = get_errand_refund_status(errand_id)
    
    # Get display status
    display_status = get_errand_display_status(errand)
    
    return render_template('shared/view_errand_details.html', 
                        errand=errand,
                        client=client,
                        runner=runner,
                        refund_status=refund_status,
                        display_status=display_status,
                        get_errand_refund_status=get_errand_refund_status,
                        get_errand_display_status=get_errand_display_status)


@bp.route('/update-errand-status/<int:errand_id>/<status>')
@login_required()
def update_errand_status(errand_id, status):
    """Update errand status - authorized users only with auto-refund for canceled errands"""
    user = User.query.get(session['user_id'])
    
    # If user is a runner, check verification
    if user.role == 'runner' and (not user.verified and user.verification_status != 'approved'):
        flash('You need to verify your account to update errand status.', 'error')
        return redirect(url_for('main.verification'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    if user.role == 'client' and errand.client_id != user.id:
        flash('You can only update your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if user.role == 'runner' and errand.runner_id != user.id:
        flash('You can only update errands you accepted.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Store old status for comparison
    old_status = errand.status
    errand.status = status
    
    # AUTO-REFUND LOGIC
    if status == 'Canceled' and errand.payment_id:
        payment = Payment.query.get(errand.payment_id)
        
        if payment and payment.payment_status == 'prepaid':
            # Process full refund to client
            success, message = process_refund(
                payment.id, 
                refund_amount=None,  # Full refund
                reason=f"Errand #{errand.id} canceled by {user.username}"
            )
            
            if success:
                # Create notification for client
                create_notification(
                    errand.client_id,
                    f'Your payment for errand #{errand.id} has been refunded to your wallet.'
                )
                flash(f'Errand canceled and payment refunded successfully!', 'success')
            else:
                flash(f'Errand canceled but refund failed: {message}', 'warning')
    
    # Update timestamps
    if status == 'Completed':
        errand.completed_at = datetime.utcnow()
    elif status == 'In Progress':
        errand.accepted_at = datetime.utcnow()
    
    db.session.commit()
    
    # Create notifications based on status change
    if status == 'Completed':
        create_notification(errand.client_id, f'Your errand #{errand.id} has been completed!')
        if errand.runner_id:
            create_notification(errand.runner_id, f'Errand #{errand.id} marked as completed. Great job!')
    elif status == 'Canceled':
        create_notification(errand.client_id, f'Your errand #{errand.id} has been canceled.')
        if errand.runner_id:
            create_notification(errand.runner_id, f'Errand #{errand.id} has been canceled by the client.')
    
    flash(f'Errand status updated to {status}', 'success')
    
    # Redirect based on user role
    if user.role == 'runner':
        return redirect(url_for('main.my_errands_runner'))
    elif user.role == 'client':
        return redirect(url_for('main.active_errands'))
    else:
        return redirect(url_for('main.dashboard'))

# ===== VERIFICATION ROUTES =====
@bp.route('/verification', methods=['GET', 'POST'])
@login_required()
def verification():
    """Unified verification page for both clients and runners"""
    user = User.query.get(session['user_id'])
    
    if user.role == 'admin':
        flash('Administrator accounts do not require verification.', 'info')
        return redirect(url_for('main.dashboard'))
    
    if user.verified:
        flash('Your account is already verified!', 'success')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        id_document = request.files.get('id_document')
        verification_type = request.form.get('verification_type')
        additional_info = request.form.get('additional_info')
        
        if not id_document:
            flash('Please upload your ID document.', 'error')
            return redirect(url_for('main.verification'))

        upload_dir = get_upload_path(user.id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Ensure directory exists
        os.makedirs(upload_dir, exist_ok=True)
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_filename = secure_filename(id_document.filename)
            filename = f"government_id_{timestamp}_{original_filename}"
            file_path = os.path.join(upload_dir, filename)
            
            print(f"DEBUG: Saving file to: {file_path}")
            print(f"DEBUG: Full file path: {os.path.abspath(file_path)}")
            
            # Save the file
            id_document.save(file_path)
            
            # Verify file was saved
            if os.path.exists(file_path):
                print(f"DEBUG: File saved successfully! Size: {os.path.getsize(file_path)} bytes")
            else:
                print(f"DEBUG: ERROR: File was not saved!")
            
            user.verification_requested = True
            user.verification_status = 'pending'
            user.last_verification_date = datetime.utcnow()
            
            if additional_info:
                user.bio = additional_info
            
            db.session.commit()
            
            admin_users = User.query.filter_by(role='admin').all()
            notification_message = f'New verification request from {user.username} ({user.role})'
            if user.verification_status == 'rejected':
                notification_message = f'Reapplication for verification from {user.username} ({user.role})'
            
            for admin in admin_users:
                create_notification(admin.id, notification_message)
            
            flash('Verification request submitted! We will review it within 24-48 hours.', 'success')
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            print(f"DEBUG: Error saving verification documents: {e}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            flash('Error saving your documents. Please try again.', 'error')
            return redirect(url_for('main.verification'))
    
    return render_template('shared/verification_request.html', 
                          user=user, 
                          show_rejection_message=user.verification_status == 'rejected')

@bp.route('/runner/check-verification')
@login_required('runner')
def check_verification():
    """Check if runner is verified (for AJAX calls)"""
    user = User.query.get(session['user_id'])
    return {'verified': user.verified, 'status': user.verification_status}


@bp.route('/view-verification-doc/<int:user_id>/<filename>')
@login_required('admin')
def view_verification_document(user_id, filename):
    user = User.query.get_or_404(user_id)
    safe_filename = secure_filename(filename)
    
    # Use the helper function
    file_path = get_upload_path(user_id, safe_filename)
    
    if not os.path.exists(file_path):
        flash('Document not found.', 'error')
        return redirect(url_for('main.admin_verify_user', user_id=user_id))
    
    # Determine content type based on file extension
    if filename.lower().endswith('.pdf'):
        mimetype = 'application/pdf'
    elif filename.lower().endswith('.png'):
        mimetype = 'image/png'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mimetype = 'image/jpeg'
    else:
        mimetype = 'application/octet-stream'
    
    # Serve the file
    return send_file(file_path, mimetype=mimetype, as_attachment=False)



# ===== ADMIN ROUTES =====#

@bp.route('/admin/users')
@login_required('admin')
def admin_users():
    """User management - admin only"""
    users = User.query.all()
    return render_template('admin/user_management.html', users=users)

@bp.route('/admin/errands')
@login_required('admin')
def admin_errands():
    """Errand management - admin only"""
    errands = Errand.query.order_by(Errand.created_at.desc()).all()
    return render_template('admin/errand_management.html', errands=errands)

@bp.route('/admin/system-config')
@login_required('admin')
def admin_system_config():
    """System configuration - admin only"""
    return render_template('admin/system_config.html')

@bp.route('/admin/reports')
@login_required('admin')
def admin_reports():
    """Admin reports page"""
    try:
        completed_errands_count = db.session.query(db.func.count(Errand.id)).filter(
            Errand.status == 'Completed'
        ).scalar()
        
        total_earnings_result = db.session.query(
            db.func.sum(db.func.coalesce(Errand.final_fee, Errand.proposed_fee))
        ).filter(
            Errand.status == 'Completed'
        ).scalar()
        total_earnings = total_earnings_result if total_earnings_result else 0
        
        today = datetime.utcnow().date()
        today_errands = db.session.query(db.func.count(Errand.id)).filter(
            db.func.date(Errand.created_at) == today
        ).scalar()
        
        active_runners = db.session.query(db.func.count(User.id)).filter(
            User.role == 'runner',
            User.is_active == True
        ).scalar()
        
        pending_verifications = db.session.query(db.func.count(User.id)).filter(
            User.verification_status == 'pending'
        ).scalar()
        
        total_users = db.session.query(db.func.count(User.id)).scalar()
        
        active_errands = db.session.query(db.func.count(Errand.id)).filter(
            Errand.status.in_(['Pending', 'Accepted', 'In Progress'])
        ).scalar()
        
        users = User.query.all()
        
        report_data = {
            'total_earnings': total_earnings,
            'active_runners': active_runners,
            'completed_errands': completed_errands_count,
            'pending_verifications': pending_verifications,
            'total_users': total_users,
            'active_errands': active_errands,
            'today_errands': today_errands
        }
        
        return render_template('admin/reports.html', 
                            report_data=report_data, 
                            users=users,
                            today_errands=today_errands,
                            now=datetime.utcnow())
    
    except Exception as e:
        print(f"ERROR in admin_reports: {str(e)}")
        import traceback
        traceback.print_exc()
        return render_template('admin/reports.html', 
                            report_data={'total_earnings': 0, 'active_runners': 0, 'completed_errands': 0, 
                                       'pending_verifications': 0, 'total_users': 0, 'active_errands': 0, 'today_errands': 0}, 
                            users=[],
                            today_errands=0,
                            now=datetime.utcnow())

@bp.route('/admin/verification-requests')
@login_required('admin')
def admin_verification_requests():
    """Verification requests management - admin only"""
    pending_clients = User.query.filter_by(role='client', verification_status='pending').all()
    pending_runners = User.query.filter_by(role='runner', verification_status='pending').all()
    
    return render_template('admin/verification_requests.html',
                        pending_clients=pending_clients,
                        pending_runners=pending_runners)

@bp.route('/admin/verify-user/<int:user_id>')
@login_required('admin')
def admin_verify_user(user_id):
    """Verify user page - admin only"""
    user = User.query.get_or_404(user_id)
    
    if user.verification_status not in ['pending', 'rejected']:
        flash('This user is not awaiting verification.', 'error')
        return redirect(url_for('main.admin_users'))
    
    documents = []
    user_folder = os.path.join('uploads', 'verification_docs', str(user.id))
    
    if os.path.exists(user_folder):
        try:
            for filename in os.listdir(user_folder):
                file_path = os.path.join(user_folder, filename)
                
                if os.path.isfile(file_path) and not filename.startswith('.'):
                    file_size = os.path.getsize(file_path)
                    upload_time = os.path.getmtime(file_path)
                    
                    doc_type = 'other'
                    if filename.startswith('government_id'):
                        doc_type = 'government_id'
                    elif filename.startswith('drivers_license'):
                        doc_type = 'drivers_license'
                    elif filename.startswith('vehicle_registration'):
                        doc_type = 'vehicle_registration'
                    elif filename.startswith('insurance'):
                        doc_type = 'insurance'
                    elif filename.startswith('proof_of_address'):
                        doc_type = 'proof_of_address'
                    
                    parts = filename.split('_')
                    if len(parts) >= 3:
                        original_name = '_'.join(parts[2:])
                    else:
                        original_name = filename
                    
                    documents.append({
                        'filename': filename,
                        'original_name': original_name,
                        'file_path': file_path,
                        'document_type': doc_type,
                        'file_size': file_size,
                        'uploaded_time': upload_time
                    })
                    
        except Exception as e:
            print(f"Error reading documents for user {user_id}: {e}")
            flash(f"Error reading documents: {str(e)}", 'error')
    
    return render_template('admin/verify_user.html', 
                         user=user, 
                         documents=documents,
                         is_reapplication=user.verification_status == 'rejected')

@bp.route('/admin/approve-user/<int:user_id>')
@login_required('admin')
def admin_approve_user(user_id):
    """Approve user verification - admin only"""
    user = User.query.get_or_404(user_id)
    user.verified = True
    user.verification_status = 'approved'
    user.verification_requested = False
    db.session.commit()
    
    create_notification(user.id, 'Your account has been verified! You can now post errands and access all features.')
    
    flash(f'{user.username} has been verified successfully!', 'success')
    return redirect(url_for('main.admin_verification_requests'))

@bp.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@login_required('admin')
def admin_reject_user(user_id):
    """Reject user verification - but allow them to reapply"""
    user = User.query.get_or_404(user_id)
    reason = request.form.get('reason', 'No reason provided')
    
    user_folder = os.path.join('uploads', 'verification_docs', str(user.id))
    archive_folder = os.path.join('uploads', 'verification_docs', str(user.id), 'archive')
    
    if os.path.exists(user_folder):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        for filename in os.listdir(user_folder):
            if os.path.isfile(os.path.join(user_folder, filename)):
                if 'archive' not in filename:
                    os.makedirs(archive_folder, exist_ok=True)
                    old_path = os.path.join(user_folder, filename)
                    new_filename = f"rejected_{timestamp}_{filename}"
                    new_path = os.path.join(archive_folder, new_filename)
                    import shutil
                    shutil.move(old_path, new_path)
    
    user.verified = False
    user.verification_status = 'rejected'
    user.verification_requested = True
    user.last_verification_date = datetime.utcnow()
    user.rejection_reason = reason
    
    db.session.commit()
    
    create_notification(user.id, f'Your verification request was rejected. Reason: {reason}. You can submit a new request with corrected documents.')
    
    flash(f'{user.username} verification rejected. User can reapply with corrected documents.', 'success')
    return redirect(url_for('main.admin_verification_requests'))

@bp.route('/admin/view-archived-documents/<int:user_id>')
@login_required('admin')
def view_archived_documents(user_id):
    """View archived verification documents - admin only"""
    user = User.query.get_or_404(user_id)
    archive_folder = os.path.join('uploads', 'verification_docs', str(user.id), 'archive')
    
    archived_docs = []
    if os.path.exists(archive_folder):
        for filename in os.listdir(archive_folder):
            if os.path.isfile(os.path.join(archive_folder, filename)):
                file_path = os.path.join(archive_folder, filename)
                file_size = os.path.getsize(file_path)
                
                timestamp = "Unknown"
                if 'rejected_' in filename:
                    try:
                        parts = filename.split('_')
                        if len(parts) >= 3:
                            date_str = parts[1]
                            time_str = parts[2]
                            timestamp = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]} {time_str[:2]}:{time_str[2:4]}:{time_str[4:6]}"
                    except:
                        pass
                
                archived_docs.append({
                    'filename': filename,
                    'file_path': file_path,
                    'file_size': file_size,
                    'timestamp': timestamp,
                    'original_name': '_'.join(filename.split('_')[3:]) if len(filename.split('_')) > 3 else filename
                })
    
    archived_docs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('admin/archived_documents.html',
                         user=user,
                         archived_docs=archived_docs)

@bp.route('/admin/view-user-documents/<int:user_id>')
@login_required('admin')
def view_user_documents(user_id):
    """View all documents for a user - admin only"""
    user = User.query.get_or_404(user_id)
    
    # Use the utility function from context processor
    from . import utility_processor
    utility_funcs = utility_processor()
    get_user_verification_documents = utility_funcs['get_user_verification_documents']
    
    documents = get_user_verification_documents(user_id)
    
    grouped_docs = {}
    for doc in documents:
        if doc['document_type'] not in grouped_docs:
            grouped_docs[doc['document_type']] = []
        grouped_docs[doc['document_type']].append(doc)
    
    return render_template('admin/user_documents.html', 
                        user=user, 
                        documents=documents,
                        grouped_docs=grouped_docs)

@bp.route('/admin/view-user/<int:user_id>')
@login_required('admin')
def view_user(user_id):
    """View user details - admin only"""
    user = User.query.get_or_404(user_id)
    return render_template('admin/view_user.html', user=user)

@bp.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required('admin')
def edit_user(user_id):
    """Edit user information - admin only"""
    edit_user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        edit_user.first_name = request.form['first_name']
        edit_user.last_name = request.form['last_name']
        edit_user.email = request.form['email']
        edit_user.phone = request.form['phone']
        edit_user.barangay = request.form['barangay']
        edit_user.role = request.form['role']
        edit_user.address = request.form.get('address', '')
        
        if edit_user.role == 'runner':
            edit_user.vehicle_type = request.form.get('vehicle_type', '')
            edit_user.available_hours = request.form.get('available_hours', '')
            edit_user.bio = request.form.get('bio', '')
        else:
            edit_user.vehicle_type = None
            edit_user.available_hours = None
            edit_user.bio = None
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('main.view_user', user_id=edit_user.id))
    
    return render_template('admin/edit_user.html', edit_user=edit_user, barangays=BARANGAYS)

@bp.route('/admin/update-errand-status/<int:errand_id>', methods=['POST'])
@login_required('admin')
def admin_update_errand_status(errand_id):
    """Update errand status - admin only"""
    errand = Errand.query.get_or_404(errand_id)
    new_status = request.form.get('status')
    
    if new_status in ['Pending', 'Accepted', 'In Progress', 'Completed', 'Canceled']:
        errand.status = new_status
        if new_status == 'Completed':
            errand.completed_at = datetime.utcnow()
        db.session.commit()
        flash(f'Errand #{errand.id} status updated to {new_status}', 'success')
    
    return redirect(url_for('main.admin_errands'))


@bp.route('/admin/payments')
@login_required('admin')
def admin_payments():
    """Admin payment management"""
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    
    # Calculate totals
    total_revenue = sum(p.platform_fee for p in payments if p.payment_status == 'released')
    total_payments = len([p for p in payments if p.payment_status == 'released'])
    pending_payments = len([p for p in payments if p.payment_status == 'prepaid'])
    
    return render_template('admin/payment_management.html',
                         payments=payments,
                         total_revenue=total_revenue,
                         total_payments=total_payments,
                         pending_payments=pending_payments)


@bp.route('/admin/payments/refund/<int:payment_id>', methods=['POST'])
@login_required('admin')
def admin_refund_payment(payment_id):
    """Admin: Process refund"""
    refund_amount = request.form.get('refund_amount')
    reason = request.form.get('reason', '')
    
    try:
        if refund_amount:
            refund_amount = float(refund_amount)
        else:
            refund_amount = None
        
        success, message = process_refund(payment_id, refund_amount, reason)
        
        if success:
            flash('Refund processed successfully!', 'success')
        else:
            flash(f'Refund failed: {message}', 'error')
            
    except Exception as e:
        flash(f'Error processing refund: {str(e)}', 'error')
    
    return redirect(url_for('main.admin_payments'))


# ===== SYSTEM CONFIG ROUTES =====
@bp.route('/api/system-config/save', methods=['POST'])
@admin_required
def save_system_config():
    """Save system configuration to database"""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        print(f"Saving system config: {data}")
        
        for key, value in data.items():
            config = SystemConfig.query.filter_by(key=key).first()
            
            if config:
                config.value = str(value)
            else:
                config = SystemConfig(key=key, value=str(value))
                db.session.add(config)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Configuration saved successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error saving system config: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/api/system-config/get', methods=['GET'])
@admin_required
def get_system_config():
    """Get all system configuration"""
    try:
        configs = SystemConfig.query.all()
        config_dict = {}
        
        for config in configs:
            config_dict[config.key] = config.value
        
        print(f"Loaded system config: {config_dict}")
        
        return jsonify({'success': True, 'config': config_dict})
    
    except Exception as e:
        print(f"Error getting system config: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/api/system-config/reset', methods=['POST'])
@admin_required
def reset_system_config():
    """Reset system configuration to defaults"""
    try:
        defaults = {
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
        
        SystemConfig.query.delete()
        
        for key, value in defaults.items():
            config = SystemConfig(key=key, value=value)
            db.session.add(config)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Configuration reset to defaults'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting system config: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500



# ===== WALLET ROUTES =====
@bp.route('/wallet')
@login_required()
def wallet():
    """User wallet dashboard - hide pending refund requests"""
    user = User.query.get(session['user_id'])
    
    # Check verification status for both clients and runners
    if not user.verified and user.verification_status != 'approved':
        # Show limited wallet view for unverified users
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        if not wallet:
            wallet = Wallet(user_id=user.id, balance=user.wallet_balance or 0.0)
            db.session.add(wallet)
            db.session.commit()
        
        # Use different templates based on role
        if user.role == 'runner':
            return render_template('wallet/wallet_unverified.html',
                                user=user,
                                wallet=wallet)
        else:  # client
            return render_template('wallet/wallet_unverified.html',
                                user=user,
                                wallet=wallet)
    
    # Regular wallet access for verified users
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    if not wallet:
        wallet = Wallet(user_id=user.id, balance=user.wallet_balance or 0.0)
        db.session.add(wallet)
        db.session.commit()
    
    # Get wallet transactions (exclude pending refund requests)
    transactions = WalletTransaction.query.filter(
        WalletTransaction.user_id == session['user_id']
    ).filter(
        ~(
            (WalletTransaction.transaction_type.in_(['refund_request', 'refund'])) &
            (WalletTransaction.status == 'pending')
        )
    ).order_by(WalletTransaction.created_at.desc()).limit(50).all()
    
    # Get payment methods
    payment_methods = PaymentMethod.query.filter_by(
        user_id=session['user_id']
    ).all()
    
    return render_template('wallet/wallet.html',
                        user=user,
                        transactions=transactions,
                        payment_methods=payment_methods,
                        wallet=wallet)


@bp.route('/wallet/deposit', methods=['POST'])
@login_required()
def wallet_deposit():
    """Deposit funds to wallet"""
    try:
        amount = float(request.form.get('amount', 0))
        method = request.form.get('method')
        
        if amount <= 0:
            flash('Please enter a valid amount.', 'error')
            return redirect(url_for('main.wallet'))
        
        if not method:
            flash('Please select a payment method.', 'error')
            return redirect(url_for('main.wallet'))
        
        # In production, this would integrate with a payment gateway
        # For now, simulate successful payment
        success, message = create_wallet_transaction(
            session['user_id'],
            'deposit',
            amount,
            f'Deposit via {method}',
            generate_transaction_id()
        )
        
        if success:
            flash(f'Successfully deposited ₱{amount:.2f} to your wallet!', 'success')
        else:
            flash(f'Deposit failed: {message}', 'error')
            
    except Exception as e:
        flash(f'Error processing deposit: {str(e)}', 'error')
    
    return redirect(url_for('main.wallet'))

@bp.route('/wallet/withdraw', methods=['POST'])
@login_required()
def wallet_withdraw():
    """Withdraw funds from wallet - requires admin approval"""
    try:
        user = User.query.get(session['user_id'])
        
        # If user is a runner, check verification
        if user.role == 'runner' and (not user.verified and user.verification_status != 'approved'):
            flash('You need to verify your account before withdrawing funds.', 'error')
            return redirect(url_for('main.wallet'))
        
        amount = float(request.form.get('amount', 0))
        method_value = request.form.get('method_id')
        
        if amount <= 0:
            flash('Please enter a valid amount.', 'error')
            return redirect(url_for('main.wallet'))
        
        if amount > user.wallet_balance:
            flash('Insufficient balance.', 'error')
            return redirect(url_for('main.wallet'))
        
        if not method_value:
            flash('Please select a withdrawal method.', 'error')
            return redirect(url_for('main.wallet'))
        
        # Generate method description
        method_description = ""
        if method_value == 'direct':
            method_description = "Direct Transfer"
        elif method_value == 'gcash':
            method_description = "GCash"
        elif method_value == 'paymaya':
            method_description = "PayMaya"
        elif method_value == 'bank':
            method_description = "Bank Transfer"
        else:
            # Try to get saved payment method
            try:
                method_id = int(method_value)
                payment_method = PaymentMethod.query.get(method_id)
                if payment_method and payment_method.user_id == user.id:
                    method_description = f"{payment_method.provider} ({payment_method.account_number})"
                else:
                    flash('Invalid withdrawal method.', 'error')
                    return redirect(url_for('main.wallet'))
            except ValueError:
                flash('Invalid withdrawal method selected.', 'error')
                return redirect(url_for('main.wallet'))
        
        # Create pending withdrawal transaction
        transaction_id = generate_transaction_id()
        
        success, message = create_wallet_transaction(
            session['user_id'],
            'withdrawal',
            -amount,  # Negative amount for withdrawal
            f'Withdrawal request to {method_description}',
            transaction_id,
            status='pending'  # Set as pending, not completed
        )
        
        if not success:
            flash(f'Withdrawal request failed: {message}', 'error')
            return redirect(url_for('main.wallet'))
        
        # Create notifications
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.id, 
                              f'New withdrawal request from {user.username} for ₱{amount:.2f} to {method_description}')
        
        create_notification(session['user_id'],
                          f'Withdrawal request for ₱{amount:.2f} submitted. Awaiting admin approval.')
        
        flash(f'Withdrawal request for ₱{amount:.2f} submitted! Please wait for admin approval.', 'success')
        
    except Exception as e:
        flash(f'Error processing withdrawal: {str(e)}', 'error')
    
    return redirect(url_for('main.wallet'))



#=========== ADMIN WALLET ROUTE ============#
@bp.route('/admin/wallet-management')
@login_required('admin')
def admin_wallet_management():
    """Unified wallet management dashboard - FOCUS ON REFUNDS ONLY"""
    from app.models import User, Payment, WalletTransaction, Errand
    
    # Only show pending refunds
    pending_refunds = WalletTransaction.query.filter(
        WalletTransaction.transaction_type == 'refund_request',
        WalletTransaction.status == 'pending'
    ).order_by(WalletTransaction.created_at.desc()).all()
    
    # Load user data for refunds
    refunds = []
    for refund in pending_refunds:
        user = User.query.get(refund.user_id)
        refund.user = user
        
        # Try to get errand info from description
        errand_id = None
        if 'errand #' in refund.description.lower():
            import re
            match = re.search(r'errand #(\d+)', refund.description)
            if match:
                errand_id = int(match.group(1))
                refund.errand = Errand.query.get(errand_id)
        
        refunds.append(refund)
    
    # Get all transactions (recent 50)
    all_transactions_query = WalletTransaction.query.filter(
        (WalletTransaction.transaction_type != 'refund_request') |
        (WalletTransaction.status != 'pending')
    ).order_by(WalletTransaction.created_at.desc()).limit(50).all()
    
    # Load user data for transactions
    all_transactions = []
    for transaction in all_transactions_query:
        user = User.query.get(transaction.user_id)
        transaction.user = user
        all_transactions.append(transaction)
    
    # Get payments (for reference only)
    payments_query = Payment.query.order_by(Payment.created_at.desc()).limit(20).all()
    
    # Load related data for payments
    payments = []
    for payment in payments_query:
        payment.errand = Errand.query.get(payment.errand_id)
        payment.client = User.query.get(payment.client_id)
        payment.runner = User.query.get(payment.runner_id) if payment.runner_id else None
        payments.append(payment)
    
    # Calculate stats
    total_users = User.query.count()
    pending_refunds_count = len(refunds)
    
    # Calculate total platform earnings
    total_platform_earnings = db.session.query(db.func.sum(Payment.platform_fee)).filter(
        Payment.payment_status == 'released'
    ).scalar() or 0
    
    # Calculate total escrow (sum of prepaid payments)
    total_escrow_result = db.session.query(db.func.sum(Payment.amount + Payment.vat_amount)).filter(
        Payment.payment_status == 'prepaid'
    ).scalar()
    total_escrow = float(total_escrow_result) if total_escrow_result else 0.0
    
    return render_template('admin/wallet_management.html',
                         refunds=refunds,
                         all_transactions=all_transactions,
                         payments=payments,
                         total_users=total_users,
                         pending_refunds_count=pending_refunds_count,
                         total_platform_earnings=float(total_platform_earnings),
                         total_escrow=total_escrow)


@bp.route('/admin/approve-withdrawal/<int:transaction_id>')
@login_required('admin')
def approve_withdrawal(transaction_id):
    """Admin approve a withdrawal request"""
    try:
        # Get the withdrawal transaction
        transaction = WalletTransaction.query.get_or_404(transaction_id)
        
        if transaction.transaction_type != 'withdrawal':
            flash('This is not a withdrawal transaction.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        if transaction.status != 'pending':
            flash(f'Withdrawal is already {transaction.status}.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Get the user
        user = User.query.get(transaction.user_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Check if user has sufficient balance
        if user.wallet_balance < abs(transaction.amount):
            flash('User has insufficient balance for this withdrawal.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Update user balance (deduct the withdrawal amount)
        # Note: amount is negative for withdrawals, so we add it (negative + negative = more negative)
        user.wallet_balance += transaction.amount  # transaction.amount is negative
        
        # Update wallet balance if wallet exists
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        if wallet:
            wallet.balance = user.wallet_balance
        
        # Update transaction status
        transaction.status = 'completed'
        transaction.balance_after = user.wallet_balance
        
        # Create notification for user
        create_notification(
            user.id,
            f'Your withdrawal of ₱{abs(transaction.amount):.2f} has been approved and processed.'
        )
        
        db.session.commit()
        
        flash(f'Withdrawal of ₱{abs(transaction.amount):.2f} approved successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error approving withdrawal: {str(e)}")
        flash(f'Error approving withdrawal: {str(e)}', 'error')
    
    return redirect(url_for('main.admin_wallet_management'))

@bp.route('/admin/reject-withdrawal/<int:transaction_id>', methods=['POST'])
@login_required('admin')
def reject_withdrawal(transaction_id):
    """Admin reject a withdrawal request"""
    try:
        transaction = WalletTransaction.query.get_or_404(transaction_id)
        reason = request.form.get('reason', 'No reason provided')
        
        if transaction.transaction_type != 'withdrawal':
            flash('This is not a withdrawal transaction.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        if transaction.status != 'pending':
            flash(f'Withdrawal is already {transaction.status}.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Update transaction status
        transaction.status = 'rejected'
        transaction.description = f'{transaction.description} [REJECTED: {reason}]'
        
        # Create notification for user
        create_notification(
            transaction.user_id,
            f'Your withdrawal request of ₱{abs(transaction.amount):.2f} was rejected. Reason: {reason}'
        )
        
        db.session.commit()
        
        flash('Withdrawal rejected successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting withdrawal: {str(e)}")
        flash(f'Error rejecting withdrawal: {str(e)}', 'error')
    
    return redirect(url_for('main.admin_wallet_management'))


# ===== PAYMENT MANAGEMENT ROUTES =====
@bp.route('/payment/history')
@login_required()
def payment_history():
    """View payment history"""
    user = User.query.get(session['user_id'])
    
    if user.role == 'client':
        payments = Payment.query.filter_by(client_id=user.id)\
            .order_by(Payment.created_at.desc()).all()
    elif user.role == 'runner':
        payments = Payment.query.filter_by(runner_id=user.id)\
            .order_by(Payment.created_at.desc()).all()
    elif user.role == 'admin':
        payments = Payment.query.order_by(Payment.created_at.desc()).all()
    else:
        payments = []
    
    return render_template('payment/history.html',
                         payments=payments,
                         user=user)

@bp.route('/payment/<int:payment_id>')
@login_required()
def view_payment(payment_id):
    """View payment details"""
    payment = Payment.query.get_or_404(payment_id)
    user = User.query.get(session['user_id'])
    
    # Verify ownership or admin access
    if (payment.client_id != user.id and 
        payment.runner_id != user.id and 
        user.role != 'admin'):
        flash('You are not authorized to view this payment.', 'error')
        return redirect(url_for('main.dashboard'))
    
    return render_template('payment/details.html',
                         payment=payment,
                         errand=payment.errand,
                         user=user)



#=========== RECEIPT ROUTES ============#
@bp.route('/receipt/<int:errand_id>')
@login_required()
def view_receipt(errand_id):
    """View receipt for an errand"""
    user = User.query.get(session['user_id'])
    errand = Errand.query.get_or_404(errand_id)
    
    # Verify ownership or admin access
    if user.role == 'client' and errand.client_id != user.id:
        flash('You can only view receipts for your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if user.role == 'runner' and errand.runner_id != user.id and user.role != 'admin':
        flash('You can only view receipts for errands you completed.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Get payment information
    payment = None
    if errand.payment_id:
        payment = Payment.query.get(errand.payment_id)
    
    # Get client and runner information
    client = User.query.get(errand.client_id)
    runner = User.query.get(errand.runner_id) if errand.runner_id else None
    
    # Calculate breakdown
    total_amount = payment.amount if payment else errand.final_fee or errand.proposed_fee
    platform_fee = payment.platform_fee if payment else total_amount * 0.10  # 10% platform fee
    vat_amount = payment.vat_amount if payment else total_amount * 0.12  # 12% VAT
    runner_earnings = payment.runner_earnings if payment else total_amount - platform_fee - vat_amount
    
    # Pass refund status
    refund_status = get_errand_refund_status(errand_id)
    
    return render_template('payment/receipt.html',  # Updated path
                        errand=errand,
                        payment=payment,
                        client=client,
                        runner=runner,
                        total_amount=total_amount,
                        platform_fee=platform_fee,
                        vat_amount=vat_amount,
                        runner_earnings=runner_earnings,
                        refund_status=refund_status,
                        user=user)


#======== REFUND ROUTES ======#
@bp.route('/request-refund/<int:errand_id>', methods=['GET', 'POST'])
@login_required('client')
def request_refund(errand_id):
    """Client requests a refund for a specific errand"""
    user = User.query.get(session['user_id'])
    errand = Errand.query.get_or_404(errand_id)
    
    # Verify ownership
    if errand.client_id != user.id:
        flash('You can only request refunds for your own errands.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Check if errand is eligible for refund
    if errand.status not in ['Completed', 'Canceled']:
        flash('Only completed or canceled errands are eligible for refund requests.', 'error')
        return redirect(url_for('main.view_errand', errand_id=errand_id))
    
    if not errand.payment_id:
        flash('No payment found for this errand.', 'error')
        return redirect(url_for('main.view_errand', errand_id=errand_id))
    
    payment = Payment.query.get(errand.payment_id)
    
    # Check if already refunded
    if payment.payment_status == 'refunded':
        flash('This payment has already been refunded.', 'info')
        return redirect(url_for('main.view_errand', errand_id=errand_id))
    
    # Check for existing pending refund request for this errand
    existing_refund = WalletTransaction.query.filter(
        WalletTransaction.user_id == user.id,
        WalletTransaction.transaction_type == 'refund_request',
        WalletTransaction.status == 'pending',
        WalletTransaction.description.like(f'%errand #{errand.id}%')
    ).first()
    
    if existing_refund:
        flash('You already have a pending refund request for this errand.', 'error')
        return redirect(url_for('main.view_errand', errand_id=errand_id))
    
    # Calculate total paid amount (amount + VAT)
    total_paid = payment.amount + payment.vat_amount
    
    if request.method == 'POST':
        reason = request.form.get('reason', '')
        amount_requested = request.form.get('amount_requested')
        
        try:
            if amount_requested:
                amount_requested = float(amount_requested)
                # FIX: Compare with total_paid instead of payment.amount
                if amount_requested > total_paid:
                    flash(f'Refund amount cannot exceed original payment (₱{total_paid:.2f}).', 'error')
                    return redirect(url_for('main.request_refund', errand_id=errand_id))
            else:
                amount_requested = total_paid  # Full refund (amount + VAT)
            
            # Create a pending refund request
            transaction_id = generate_transaction_id()
            
            # Create notification for admins
            admin_users = User.query.filter_by(role='admin').all()
            for admin in admin_users:
                create_notification(
                    admin.id,
                    f'New refund request from {user.username} for errand #{errand.id}. Amount: ₱{amount_requested:.2f}. Reason: {reason}'
                )
            
            description = f'Refund request for errand #{errand.id}. Amount: ₱{amount_requested:.2f}. Reason: {reason}'

            refund_request = WalletTransaction(
                user_id=user.id,
                wallet_id=user.wallet_balance,
                transaction_type='refund_request',
                amount=amount_requested,  # Store the actual refund amount
                balance_before=user.wallet_balance,
                balance_after=user.wallet_balance, 
                description=description,
                reference_id=f'ERRAND_{errand.id}',
                status='pending'
            )
            
            db.session.add(refund_request)
            db.session.commit()
            
            create_notification(
                user.id,
                f'Refund request for errand #{errand.id} submitted. Awaiting admin review.'
            )
            
            flash('Refund request submitted! Admin will review your request.', 'success')
            return redirect(url_for('main.view_errand', errand_id=errand_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting refund request: {str(e)}', 'error')
    
    # Pass total_paid to template
    return render_template('client/request_refund.html',
                         user=user,
                         errand=errand,
                         payment=payment,
                         total_paid=total_paid)



@bp.route('/admin/approve-refund/<int:transaction_id>')
@login_required('admin')
def approve_refund(transaction_id):
    try:
        transaction = WalletTransaction.query.get_or_404(transaction_id)
        
        if transaction.transaction_type != 'refund_request':
            flash('This is not a refund request.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        if transaction.status != 'pending':
            flash(f'Refund is already {transaction.status}.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        user = User.query.get(transaction.user_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Get refund amount from transaction
        # This should be the full amount the user requested
        refund_amount = transaction.amount
        
        # Make sure amount is positive for adding to wallet
        if refund_amount <= 0:
            refund_amount = abs(refund_amount)
        
        # Update user balance (ADD the refund amount)
        user.wallet_balance += refund_amount
        
        # Update wallet
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        if wallet:
            wallet.balance = user.wallet_balance
        
        # Update the transaction record
        transaction.balance_before = user.wallet_balance - refund_amount
        transaction.balance_after = user.wallet_balance
        transaction.status = 'completed'
        transaction.transaction_type = 'refund'
        transaction.amount = refund_amount  # Ensure it's positive
        
        # Update payment status if applicable
        if 'errand #' in transaction.description.lower():
            try:
                import re
                match = re.search(r'errand #(\d+)', transaction.description, re.IGNORECASE)
                if match:
                    errand_id = int(match.group(1))
                    errand = Errand.query.get(errand_id)
                    if errand and errand.payment_id:
                        payment = Payment.query.get(errand.payment_id)
                        if payment:
                            payment.payment_status = 'refunded'
                            payment.refunded_at = datetime.utcnow()
            except Exception as e:
                print(f"Error updating payment status: {e}")
                # Don't fail the whole process
        
        # Create notification
        create_notification(
            user.id,
            f'Your refund request for ₱{refund_amount:.2f} has been approved and credited to your wallet.'
        )
        
        db.session.commit()
        
        flash(f'Refund of ₱{refund_amount:.2f} approved successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error approving refund: {str(e)}")
        flash(f'Error approving refund: {str(e)}', 'error')
    
    return redirect(url_for('main.admin_wallet_management'))


@bp.route('/admin/reject-refund/<int:transaction_id>', methods=['POST'])
@login_required('admin')
def reject_refund(transaction_id):
    """Admin reject a refund request - SIMPLE FIX"""
    try:
        transaction = WalletTransaction.query.get_or_404(transaction_id)
        reason = request.form.get('reason', 'No reason provided')
        
        if transaction.transaction_type != 'refund_request':
            flash('This is not a refund request.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        if transaction.status != 'pending':
            flash(f'Refund is already {transaction.status}.', 'error')
            return redirect(url_for('main.admin_wallet_management'))
        
        # Get refund amount for notification
        refund_amount = transaction.amount
        
        # Update transaction - show amount as 0 or negative to indicate no money added
        transaction.status = 'rejected'
        transaction.amount = 0.0  # Set to 0 so it doesn't show as positive
        transaction.description = f"{transaction.description} [REJECTED: {reason}]"
        transaction.balance_after = transaction.balance_before  # No change
        
        # Create notification
        create_notification(
            transaction.user_id,
            f'Your refund request of ₱{refund_amount:.2f} was rejected. Reason: {reason}'
        )
        
        db.session.commit()
        
        flash(f'Refund request rejected successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting refund: {str(e)}")
        flash(f'Error rejecting refund: {str(e)}', 'error')
    
    return redirect(url_for('main.admin_wallet_management'))






# ===== ERROR HANDLERS =====
@bp.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500