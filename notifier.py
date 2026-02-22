"""
Traccar sync service — email notifier

Sends HTML+text email notifications via SMTP when:
  - re-authentication is required (Google OAuth token expired)
  - a new device is discovered and auto-registered
  - a test is triggered via POST /notify/test

Configuration (environment variables or Traccar/.env):
    NOTIFY_SMTP_HOST     SMTP server hostname  (required to enable notifications)
    NOTIFY_SMTP_PORT     SMTP port             (default: 587)
    NOTIFY_SMTP_USER     SMTP login username
    NOTIFY_SMTP_PASS     SMTP login password
    NOTIFY_EMAIL_FROM    Sender address        (defaults to NOTIFY_SMTP_USER)
    NOTIFY_EMAIL_TO      Recipient(s), comma-separated  (required)
    NOTIFY_SMTP_SSL      'true' to use SSL on connect instead of STARTTLS (default: false)

NOTE: env vars are read lazily inside send_notification() so that load_dotenv()
called by service.py at startup is guaranteed to run first.
"""

import os
import html
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger('traccar_service')

# Accent colours per alert level
_COLORS = {
    'info':    '#1a73e8',   # Google blue
    'success': '#34a853',   # Google green
    'warning': '#f9ab00',   # Google amber
    'error':   '#ea4335',   # Google red
}

_ICONS = {
    'info':    '&#128205;',  # 📍
    'success': '&#10003;',   # ✓
    'warning': '&#9888;',    # ⚠
    'error':   '&#128680;',  # 🚨
}


def _build_html(subject: str, body: str, color: str, icon: str) -> str:
    """Returns a styled HTML email string (inline CSS for maximum client compatibility)."""
    escaped_subject = html.escape(subject)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Split on double newlines → paragraphs; preserve internal spacing with pre-wrap
    paragraphs = html.escape(body).split('\n\n')
    body_html = ''.join(
        f'<p style="margin:0 0 16px 0;white-space:pre-wrap;line-height:1.7;">{p.strip()}</p>'
        for p in paragraphs if p.strip()
    )

    return f"""\
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_subject}</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0"
         style="background:#f0f4f8;padding:40px 16px;">
    <tr><td align="center">

      <!-- Card -->
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:10px;overflow:hidden;
                    box-shadow:0 2px 16px rgba(0,0,0,0.09);max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:{color};padding:28px 32px;text-align:center;">
            <div style="color:#ffffff;font-size:28px;font-weight:bold;
                        letter-spacing:2px;line-height:1;">
              {icon}&nbsp;FineTrack
            </div>
            <div style="color:rgba(255,255,255,0.8);font-size:13px;margin-top:8px;">
              Google Find My &rarr; Traccar Sync
            </div>
          </td>
        </tr>

        <!-- Subject bar -->
        <tr>
          <td style="padding:28px 32px 12px 32px;border-bottom:3px solid {color};">
            <div style="font-size:19px;font-weight:bold;color:#1a1a1a;line-height:1.3;">
              {escaped_subject}
            </div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:24px 32px 32px 32px;font-size:15px;color:#444444;">
            {body_html}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8f9fa;padding:14px 32px;
                     text-align:center;border-top:1px solid #e9ecef;">
            <span style="color:#aaa;font-size:12px;">
              FineTrack Sync &middot; {now_str}
            </span>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def send_notification(subject: str, body: str, alert_level: str = 'info') -> None:
    """
    Sends a styled HTML + plain-text email notification.

    alert_level: 'info' | 'success' | 'warning' | 'error'
      Controls the header accent colour and icon.

    Reads SMTP configuration from environment at call time (not at import time)
    so that load_dotenv() in service.py is always applied first.
    No-op (with a warning log) if NOTIFY_SMTP_HOST or NOTIFY_EMAIL_TO is not set.
    Errors during sending are caught and logged — they never crash the caller.
    """
    host      = os.environ.get('NOTIFY_SMTP_HOST', '').strip()
    to        = os.environ.get('NOTIFY_EMAIL_TO',   '').strip()

    if not host or not to:
        logger.warning(f"[notify] SMTP not configured — skipped: {subject}")
        return

    port      = int(os.environ.get('NOTIFY_SMTP_PORT', '587'))
    user      = os.environ.get('NOTIFY_SMTP_USER', '').strip()
    pw        = os.environ.get('NOTIFY_SMTP_PASS', '').strip()
    from_addr = os.environ.get('NOTIFY_EMAIL_FROM', '').strip() or user
    use_ssl   = os.environ.get('NOTIFY_SMTP_SSL', 'false').strip().lower() in ('1', 'true', 'yes')

    color = _COLORS.get(alert_level, _COLORS['info'])
    icon  = _ICONS.get(alert_level,  _ICONS['info'])

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = from_addr
    msg['To']      = to

    msg.attach(MIMEText(body,                              'plain', 'utf-8'))
    msg.attach(MIMEText(_build_html(subject, body, color, icon), 'html',  'utf-8'))

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
                if user and pw:
                    smtp.login(user, pw)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if user and pw:
                    smtp.login(user, pw)
                smtp.send_message(msg)
        logger.info(f"[notify] Email sent → {to} | {subject}")
    except Exception as exc:
        logger.error(f"[notify] Failed to send email to {to}: {exc}")
