"""
Email service -- sends verification, password-reset, and admin-notification
emails via SMTP.

In test mode (``EMAIL_TEST_MODE = True``) emails are captured in memory
(``_sent_emails``) instead of being sent, so tests can assert on them.
"""
import logging
from datetime import datetime

from flask import current_app

_logger = logging.getLogger("email_service")

# In-memory capture for tests
_sent_emails = []


class EmailResult:
    """Simple result object indicating whether an email was sent."""

    def __init__(self, success=True, error=None, to=None, subject=None):
        self.success = success
        self.error = error
        self.to = to
        self.subject = subject


def _smtp_config():
    """Extract SMTP settings from the current app config."""
    app = current_app._get_current_object()
    return {
        "host": app.config.get("SMTP_HOST", "localhost"),
        "port": int(app.config.get("SMTP_PORT", 587)),
        "user": app.config.get("SMTP_USER", ""),
        "password": app.config.get("SMTP_PASSWORD", ""),
        "use_tls": app.config.get("SMTP_USE_TLS", True),
        "from_addr": app.config.get("EMAIL_FROM", "noreply@university.edu"),
    }


def send_email(to, subject, body, html=False):
    """Send a single email via SMTP.

    Returns an ``EmailResult``.
    In test mode the email is captured in ``_sent_emails`` and no SMTP
    connection is attempted.
    """
    app = current_app._get_current_object()
    if app.config.get("EMAIL_TEST_MODE", False):
        msg = {
            "to": to,
            "subject": subject,
            "body": body,
            "html": html,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        _sent_emails.append(msg)
        return EmailResult(success=True, to=to, subject=subject)

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        cfg = _smtp_config()
        if not to:
            return EmailResult(success=False, error="No recipient")

        if html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(body, "html"))
        else:
            msg = MIMEText(body, "plain")

        msg["Subject"] = subject
        msg["From"] = cfg["from_addr"]
        msg["To"] = to

        server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
        if cfg["use_tls"]:
            server.starttls()
        if cfg["user"] and cfg["password"]:
            server.login(cfg["user"], cfg["password"])
        server.sendmail(cfg["from_addr"], [to], msg.as_string())
        server.quit()
        return EmailResult(success=True, to=to, subject=subject)
    except Exception as exc:
        _logger.error("Failed to send email to %s: %s", to, exc)
        return EmailResult(success=False, error=str(exc), to=to, subject=subject)


def verification_email_body(base_url, token, user_type, name):
    """Build the plain-text verification email body."""
    path = f"/{user_type}/verify-email/{token}"
    link = f"{base_url}{path}"
    return (
        f"Dear {name},\n\n"
        f"Please verify your email address by clicking the link below:\n\n"
        f"{link}\n\n"
        f"This link expires in 24 hours.\n\n"
        f"If you did not request this, please ignore this email."
    )


def password_reset_email_body(base_url, token, user_type, name):
    """Build the plain-text password-reset email body."""
    path = f"/{user_type}/reset-password/{token}"
    link = f"{base_url}{path}"
    return (
        f"Dear {name},\n\n"
        f"You requested a password reset.  Click the link below to set a "
        f"new password:\n\n"
        f"{link}\n\n"
        f"This link expires in 2 hours.\n\n"
        f"If you did not request this, please ignore this email."
    )


def lecturer_pending_notification(admin_email, name, email):
    """Notify admin that a lecturer needs approval."""
    body = (
        f"A new lecturer has registered and needs your approval.\n\n"
        f"Name:   {name}\n"
        f"Email:  {email}\n\n"
        f"Please log in to the admin dashboard to review pending registrations."
    )
    return send_email(admin_email, "New Lecturer Registration Pending Approval", body)


def get_sent_emails():
    """Return the list of captured emails (test mode)."""
    return list(_sent_emails)


def clear_sent_emails():
    """Clear the captured email list (call between tests)."""
    _sent_emails.clear()
