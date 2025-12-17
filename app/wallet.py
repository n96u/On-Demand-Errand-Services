# app/wallet.py
from datetime import datetime
import random
import string
from decimal import Decimal, ROUND_HALF_UP
from app import db
from app.models import User, Wallet, WalletTransaction, Payment


def generate_transaction_id():
    """Generate unique transaction ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f'TXN{timestamp}{random_str}'

def calculate_fees(amount):
    """Calculate platform fee, VAT, and runner earnings"""
    amount_decimal = Decimal(str(amount))
    platform_fee = (amount_decimal * Decimal('0.10')).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP)
    vat_amount = ((amount_decimal + platform_fee) * Decimal('0.12')).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP)
    runner_earnings = (amount_decimal - platform_fee).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP)
    total_amount = (amount_decimal + vat_amount).quzantize(Decimal('0.00'), rounding=ROUND_HALF_UP)
    
    return {
        'amount': float(amount_decimal),
        'platform_fee': float(platform_fee),
        'vat_amount': float(vat_amount),
        'runner_earnings': float(runner_earnings),
        'total_amount': float(total_amount)
    }

def create_wallet_transaction(user_id, transaction_type, amount, description="", reference_id="", status="completed"):
    """Create wallet transaction and update user balance"""
    try:
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Get or create wallet
        wallet = Wallet.query.filter_by(user_id=user_id).first()
        if not wallet:
            wallet = Wallet(user_id=user_id, balance=user.wallet_balance or 0.0)
            db.session.add(wallet)
            db.session.flush()
        
        balance_before = user.wallet_balance
        user.wallet_balance += amount
        balance_after = user.wallet_balance
        
        # Update wallet balance
        wallet.balance = user.wallet_balance
        
        # Update totals based on transaction type
        if transaction_type == 'payment' and status == 'completed':
            user.total_spent += abs(amount)
        elif transaction_type == 'earnings' and status == 'completed':
            user.total_earnings += amount
        
        # Create transaction record
        transaction = WalletTransaction(
            user_id=user_id,
            wallet_id=wallet.id,
            transaction_type=transaction_type,
            amount=amount,
            balance_before=balance_before,
            balance_after=balance_after,
            description=description,
            reference_id=reference_id,
            status=status
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return True, "Transaction completed"
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in create_wallet_transaction: {str(e)}")
        return False, str(e)

# app/wallet.py
def process_errand_payment(client_id, runner_id, errand_id, amount, payment_method, use_wallet=False):
    """Process payment for an errand"""
    try:
        # Calculate fees
        fees = calculate_fees(amount)
        
        # Generate transaction ID
        transaction_id = generate_transaction_id()
        
        # Create payment record
        payment = Payment(
            transaction_id=transaction_id,
            errand_id=errand_id,
            client_id=client_id,
            runner_id=runner_id,
            amount=fees['amount'],
            platform_fee=fees['platform_fee'],
            vat_amount=fees['vat_amount'],
            runner_earnings=fees['runner_earnings'],
            payment_method=payment_method,
            payment_status='prepaid' if use_wallet else 'pending',
            paid_at=datetime.utcnow() if use_wallet else None
        )
        
        db.session.add(payment)
        
        # If using wallet, deduct from client's wallet
        if use_wallet:
            success, message = create_wallet_transaction(
                client_id,
                'payment',
                -fees['total_amount'],  # Negative amount for payment
                f'Payment for errand #{errand_id}',
                transaction_id
            )
            
            if not success:
                return False, message, None
        
        db.session.commit()
        return True, "Payment processed successfully", payment
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in process_errand_payment: {str(e)}")
        return False, str(e), None
    

def auto_release_payment_to_runner(payment_id):
    """Automatically release escrow payment to runner when errand is completed"""
    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return False, "Payment not found"
        
        if payment.payment_status != 'prepaid':
            return False, f"Payment is not in prepaid status. Current status: {payment.payment_status}"
        
        if not payment.runner_id:
            return False, "No runner assigned to this payment"
        
        # Release to runner's wallet
        success, message = create_wallet_transaction(
            payment.runner_id,
            'earnings',
            payment.runner_earnings,
            f'Earnings from errand #{payment.errand_id}',
            payment.transaction_id
        )
        
        if not success:
            return False, message
        
        # Update payment status
        payment.payment_status = 'released'
        payment.released_at = datetime.utcnow()
        
        db.session.commit()
        return True, "Payment automatically released to runner"
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in auto_release_payment_to_runner: {str(e)}")
        return False, str(e)


def process_refund(payment_id, refund_amount=None, reason=""):
    """Process refund for a payment"""
    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return False, "Payment not found"
        
        # Determine refund amount
        if refund_amount is None:
            # FIX: Include VAT in the refund
            refund_amount = payment.amount + payment.vat_amount
        
        # Check if payment can be refunded
        if payment.payment_status not in ['prepaid', 'released']:
            return False, f"Cannot refund payment with status: {payment.payment_status}"
        
        # Refund to client's wallet
        success, message = create_wallet_transaction(
            payment.client_id,
            'refund',
            refund_amount,
            f'Refund for payment {payment.transaction_id}: {reason}',
            f"REF_{payment.transaction_id}"
        )
        
        if not success:
            return False, message
        
        # Update payment status
        payment.payment_status = 'refunded'
        payment.refunded_at = datetime.utcnow()
        
        db.session.commit()
        return True, "Refund processed successfully"
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in process_refund: {str(e)}")
        return False, str(e)