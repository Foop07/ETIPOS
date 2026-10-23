import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import timedelta

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM", f"ETIPOS <{SMTP_USER}>")


def send_transfer_email(to_email: str, magnet_link: str, pin: str, filename: str, expires_in_seconds: int) -> bool:
    """
    Send an email with a P2P file transfer link.
    
    Args:
        to_email: Recipient email address
        magnet_link: WebTorrent magnet link
        pin: 6-digit PIN for access
        filename: Name of the file being transferred
        expires_in_seconds: Time until the transfer expires
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Calculate expiry time in human-readable format
        if expires_in_seconds < 3600:
            expiry_str = f"{expires_in_seconds // 60} minutes"
        elif expires_in_seconds < 86400:
            expiry_str = f"{expires_in_seconds // 3600} hours"
        else:
            expiry_str = f"{expires_in_seconds // 86400} days"
        
        # Build email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"File Transfer: {filename}"
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        
        # Plain text version
        text_body = f"""
ETIPOS File Transfer

Someone has sent you a file: {filename}

Your PIN: {pin}

Magnet Link: {magnet_link}

This transfer will expire in {expiry_str}.

To download the file, use your PIN to access the transfer.
"""
        
        # HTML version
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #0066cc; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; }}
        .pin {{ font-size: 24px; font-weight: bold; color: #0066cc; text-align: center; padding: 15px; background: white; border: 2px solid #0066cc; margin: 20px 0; }}
        .magnet {{ word-break: break-all; font-size: 12px; color: #666; background: #fff; padding: 10px; border: 1px solid #ddd; }}
        .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 ETIPOS File Transfer</h1>
        </div>
        <div class="content">
            <p>Someone has sent you a file:</p>
            <h2>{filename}</h2>
            
            <p><strong>Your PIN:</strong></p>
            <div class="pin">{pin}</div>
            
            <p><strong>Magnet Link:</strong></p>
            <div class="magnet">{magnet_link}</div>
            
            <p><strong>⏱️ Expires in:</strong> {expiry_str}</p>
        </div>
        <div class="footer">
            <p>This is an automated message from ETIPOS Secure File Transfer.</p>
            <p>Use your PIN to access the transfer before it expires.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Attach both versions
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email via SMTP
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
        
        return True
    
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
