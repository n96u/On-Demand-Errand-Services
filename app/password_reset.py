from datetime import datetime, timedelta
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app import db
from app.models import User, PasswordResetToken
import os

def generate_reset_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def create_password_reset_token(user_id):
    """Create a password reset token for a user"""
    # Delete any existing tokens for this user
    PasswordResetToken.query.filter_by(user_id=user_id).delete()
    
    # Create new token
    token = generate_reset_token()
    expires_at = datetime.utcnow() + timedelta(hours=24)  # Token valid for 24 hours
    
    reset_token = PasswordResetToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at
    )
    
    db.session.add(reset_token)
    db.session.commit()
    
    return token

def validate_reset_token(token):
    """Validate a password reset token"""
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token:
        return None, "Invalid or expired token"
    
    if not reset_token.is_valid():
        return None, "Token has expired or already been used"
    
    return reset_token.user, None

def mark_token_used(token):
    """Mark a token as used"""
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if reset_token:
        reset_token.used = True
        db.session.commit()

def send_password_reset_email(user, token):
    """Send password reset email to user"""
    try:
        # In production, configure these in environment variables
        smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.environ.get('SMTP_PORT', 587))
        smtp_username = os.environ.get('SMTP_USERNAME', '')
        smtp_password = os.environ.get('SMTP_PASSWORD', '')
        from_email = os.environ.get('FROM_EMAIL', 'noreply@grabitdone.com')
        
        # For local testing, we'll simulate sending email
        if not all([smtp_username, smtp_password]):
            print(f"Password reset link for {user.email}:")
            print(f"http://localhost:5000/reset-password/{token}")
            return True, "Reset link generated (check console for local testing)"
        
        # Create email
        reset_url = f"http://localhost:5000/reset-password/{token}"
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Password Reset Request - GrabItDone'
        msg['From'] = from_email
        msg['To'] = user.email
        
        # Create HTML email
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #c9b59c, #a68b6f); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f9f9f9; }}
                .button {{ display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #c9b59c, #a68b6f); color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }}
                .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>GrabItDone</h1>
                    <h2>Password Reset</h2>
                </div>
                <div class="content">
                    <p>Hello {user.first_name or user.username},</p>
                    <p>You requested to reset your password for your GrabItDone account.</p>
                    <p>Click the button below to create a new password:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="background: #eee; padding: 10px; border-radius: 3px; word-break: break-all;">
                        {reset_url}
                    </p>
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} GrabItDone. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Attach HTML
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        
        return True, "Password reset email sent successfully"
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return False, f"Error sending email: {str(e)}"