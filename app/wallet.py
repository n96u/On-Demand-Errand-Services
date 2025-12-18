from datetime import datetime
import random
import string
from decimal import Decimal, ROUND_HALF_UP
from app import db
from app.models import User, Wallet, WalletTransaction, Payment, SystemConfig

def generate_transaction_id():
    """Generate unique transaction ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f'TXN{timestamp}{random_str}'

def get_config_value(key, default):
    """Helper to get system config value safely"""
    try:
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            return float(config.value)
    except Exception:
        pass
    return default

def get_platform_wallet():

    admin = User.query.filter_by(role='admin').order_by(User.id.asc()).first()
    
    if not admin:
        return None
        
    wallet = Wallet.query.filter_by(user_id=admin.id).first()
    if not wallet:
        wallet = Wallet(user_id=admin.id, balance=0.0)
        db.session.add(wallet)
        db.session.commit()
        
    return wallet


def calculate_fees(subtotal_amount):
    amount = float(subtotal_amount)
    vat_rate = get_config_value('vatRate', 12.00) / 100
    commission_rate = get_config_value('platformCommission', 10.00) / 100
    vat_amount = amount * vat_rate
    total_amount = amount + vat_amount
    platform_fee = amount * commission_rate
    runner_earnings = amount - platform_fee
    
    return {
        'amount': amount,
        'total_amount': total_amount, 
        'platform_fee': platform_fee, 
        'vat_amount': vat_amount,
        'runner_earnings': runner_earnings
    }

def create_wallet_transaction(user_id, transaction_type, amount, description, reference_id, status='completed'):
    try:
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
            
        wallet = Wallet.query.filter_by(user_id=user_id).first()
        if not wallet:
            wallet = Wallet(user_id=user_id, balance=0.0)
            db.session.add(wallet)
            
        transaction = WalletTransaction(
            user_id=user_id,
            wallet_id=wallet.id,
            transaction_type=transaction_type,
            amount=amount,
            description=description,
            reference_id=reference_id,
            status=status,
            balance_before=wallet.balance,
            balance_after=wallet.balance + amount if status == 'completed' else wallet.balance
        )
        db.session.add(transaction)
        
        # 3. UPDATE BALANCE (The Missing Link)
        if status == 'completed':
            # Update the Wallet Model
            wallet.balance += float(amount)
            

            user.wallet_balance = wallet.balance 
            
        db.session.commit()
        return True, "Transaction successful"
        
    except Exception as e:
        db.session.rollback()
        print(f"Wallet Error: {e}")
        return False, str(e)

def process_errand_payment(errand_id, client_id, amount, payment_method='wallet'):
    """Process payment for an errand"""
    try:
        fees = calculate_fees(amount)
        transaction_id = generate_transaction_id()
        
        payment = Payment(
            transaction_id=transaction_id,
            errand_id=errand_id,
            client_id=client_id,
            amount=fees['amount'],
            platform_fee=fees['platform_fee'],
            vat_amount=fees['vat_amount'],
            runner_earnings=fees['runner_earnings'],
            payment_method=payment_method,
            payment_status='pending'
        )
        
        db.session.add(payment)
        return True, payment
        
    except Exception as e:
        print(f"Error processing payment: {e}")
        return False, None

def process_vat_transfer(errand_id, vat_amount):
    """
    Credits VAT to the platform wallet immediately upon errand creation.
    """
    try:
        platform_wallet = get_platform_wallet()
        if not platform_wallet:
            return False, "Platform wallet not found"

        # Credit Platform Wallet
        platform_wallet.balance += float(vat_amount)
        
        # Record Transaction
        txn = WalletTransaction(
            wallet_id=platform_wallet.id,
            user_id=platform_wallet.user_id,
            amount=vat_amount,
            transaction_type='credit', # earning
            description=f"VAT collected for Errand #{errand_id}",
            status='completed',
            reference_id=f"VAT_{errand_id}",
            balance_before=platform_wallet.balance - float(vat_amount),
            balance_after=platform_wallet.balance
        )
        
        db.session.add(txn)
        return True, "VAT transferred"
    except Exception as e:
        print(f"Error processing VAT: {e}")
        return False, str(e)

def process_commission_transfer(errand_id, commission_amount):
    """
    Credits Platform Commission to the platform wallet upon completion.
    """
    try:
        platform_wallet = get_platform_wallet()
        if not platform_wallet:
            return False, "Platform wallet not found"

        # Credit Platform Wallet
        platform_wallet.balance += float(commission_amount)
        
        # Record Transaction
        txn = WalletTransaction(
            wallet_id=platform_wallet.id,
            user_id=platform_wallet.user_id,
            amount=commission_amount,
            transaction_type='credit', # earning
            description=f"Platform Commission for Errand #{errand_id}",
            status='completed',
            reference_id=f"COM_{errand_id}",
            balance_before=platform_wallet.balance - float(commission_amount),
            balance_after=platform_wallet.balance
        )
        
        db.session.add(txn)
        return True, "Commission transferred"
    except Exception as e:
        print(f"Error processing Commission: {e}")
        return False, str(e)

def process_refund(payment_id, refund_amount=None, reason=""):
    """Process refund for a payment"""
    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return False, "Payment not found"
        
        # Calculate max refund (Total paid by client)
        max_refund = payment.amount + payment.vat_amount
        
        if refund_amount is None:
            refund_amount = max_refund
        else:
            refund_amount = float(refund_amount)
            
        if refund_amount > max_refund:
            return False, f"Refund amount cannot exceed ₱{max_refund:.2f}"
        
        # Check if payment can be refunded
        if payment.payment_status not in ['prepaid', 'released']:
            return False, f"Cannot refund payment with status: {payment.payment_status}"
            
        # HANDLE PLATFORM WALLET DEDUCTION (VAT Return)
        # If we are refunding, we must take the VAT back from the admin wallet
        # to ensure the money exists to pay the client back.
        platform_wallet = get_platform_wallet()
        
        # Pro-rate VAT return if partial refund, otherwise full VAT
        vat_to_return = payment.vat_amount
        if refund_amount < max_refund:
            vat_to_return = (refund_amount / max_refund) * payment.vat_amount

        if platform_wallet and platform_wallet.balance >= vat_to_return:
            platform_wallet.balance -= vat_to_return
            
            # Log deduction from platform
            plat_txn = WalletTransaction(
                wallet_id=platform_wallet.id,
                user_id=platform_wallet.user_id,
                amount=-vat_to_return,
                transaction_type='debit',
                description=f"VAT Reversal for Refund #{payment.transaction_id}",
                status='completed',
                reference_id=f"VAT_REV_{payment.transaction_id}",
                balance_before=platform_wallet.balance + vat_to_return,
                balance_after=platform_wallet.balance
            )
            db.session.add(plat_txn)
        
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
        print(f"Error in process_refund: {e}")
        return False, str(e)