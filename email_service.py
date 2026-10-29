import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER") or os.getenv("GMAIL_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or os.getenv("GMAIL_APP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM", f"ETIPOS Relay <{SMTP_USER}>" if SMTP_USER else "ETIPOS Relay")


def send_transfer_email(
    to_email: str,
    download_url: str,
    filename: str,
    size_bytes: int = 0,
    expires_in_hours: int = 24,
    sender_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send an email with the secure direct download link.
    Works with standard Gmail SMTP using an App Password.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        return {
            "success": False,
            "error": "SMTP_USER and SMTP_PASSWORD (or GMAIL_USER / GMAIL_APP_PASSWORD) not configured."
        }

    sender_display = sender_name or "Someone"

    def format_size(bytes_val: int) -> str:
        if bytes_val <= 0:
            return "Unknown size"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"

    readable_size = format_size(size_bytes)
    subject = f"[ETIPOS] {sender_display} sent you a secure file: {filename}"

    text_body = f"""
ETIPOS Secure File Transfer

{sender_display} has sent you a file: {filename}
Size: {readable_size}
Lifespan: {expires_in_hours} hours

Download link:
{download_url}

This file was analyzed locally by ETIPOS zero-trust multi-tier security pipeline.
The file will be securely deleted once downloaded or upon expiration.
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #0d0f12;
      color: #e6edf3;
      padding: 24px;
      margin: 0;
    }}
    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      max-width: 520px;
      margin: 0 auto;
      padding: 28px;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: #58a6ff;
      background: rgba(56, 139, 253, 0.15);
      border-radius: 20px;
      margin-bottom: 16px;
    }}
    h2 {{
      margin: 0 0 12px 0;
      color: #f0f6fc;
      font-size: 20px;
    }}
    .details {{
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 14px 18px;
      margin: 18px 0;
    }}
    .row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 13px;
    }}
    .row:last-child {{
      margin-bottom: 0;
    }}
    .label {{
      color: #8b949e;
    }}
    .val {{
      color: #c9d1d9;
      font-weight: 500;
      word-break: break-all;
    }}
    .btn {{
      display: block;
      width: 100%;
      box-sizing: border-box;
      text-align: center;
      background: #238636;
      color: #ffffff !important;
      text-decoration: none;
      font-weight: 600;
      padding: 14px 0;
      border-radius: 6px;
      margin: 24px 0 16px 0;
      font-size: 15px;
    }}
    .footer {{
      font-size: 12px;
      color: #8b949e;
      text-align: center;
      margin-top: 20px;
      line-height: 1.5;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">ETIPOS SECURE RELAY</div>
    <h2>File Ready for Download</h2>
    <p style="color: #8b949e; font-size: 14px; margin: 0 0 16px 0;">
      <strong>{sender_display}</strong> shared a verified safe file with you.
    </p>

    <div class="details">
      <div class="row"><span class="label">File name</span><span class="val">{filename}</span></div>
      <div class="row"><span class="label">Size</span><span class="val">{readable_size}</span></div>
      <div class="row"><span class="label">Expires in</span><span class="val">{expires_in_hours} hours</span></div>
    </div>

    <a href="{download_url}" class="btn">Download File</a>

    <div class="footer">
      Link expires in {expires_in_hours} hours.<br>
      Analyzed by ETIPOS Multi-Tier Security (Magika · ClamAV · Qwen AI)
    </div>
  </div>
</body>
</html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, msg.as_string())
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
