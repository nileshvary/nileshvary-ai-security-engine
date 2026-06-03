"""Gmail SMTP notifier for new-signup and premium-request notifications.

Reads credentials from ``st.secrets["smtp"]``:

::

    [smtp]
    host = "smtp.gmail.com"
    port = 587
    user = "youraccount@gmail.com"
    password = "<16-char Gmail app password>"
    from_email = "youraccount@gmail.com"
    to_email = "nileshvary@gmail.com"

When the section is missing the helper silently logs an INFO message
and returns ``False`` so the app degrades gracefully — users can still
sign up, the operator just doesn't get the heads-up email.
"""

from __future__ import annotations

import datetime as _dt
import logging
import smtplib
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_TO_EMAIL = "nileshvary@gmail.com"


def send_admin_notification(
    email: str,
    name: str,
    reason: str,
    *,
    secrets: Any | None = None,
    subject: str | None = None,
) -> bool:
    """Send a notification email to the RemediAX admin.

    Args:
        email: The new user's (or requester's) email.
        name: Display name on the request.
        reason: Free-form note — for sign-ups this is "new signup", for
            premium requests it's the user-supplied justification.
        secrets: Streamlit-secrets-shaped mapping; when ``None`` the
            function attempts to read ``st.secrets`` and falls back to
            no-op if Streamlit isn't running.
        subject: Override the default email subject.

    Returns:
        ``True`` when the email was delivered to the SMTP server,
        ``False`` when SMTP is not configured or sending failed.
    """
    cfg = _load_smtp_config(secrets)
    if cfg is None:
        logger.info("SMTP not configured; skipping admin notification for %s", email)
        return False

    message = EmailMessage()
    message["Subject"] = subject or f"[RemediAX] New event from {name}"
    message["From"] = cfg["from_email"]
    message["To"] = cfg["to_email"]
    message.set_content(_format_body(email, name, reason))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(message)
    except Exception as exc:  # pragma: no cover - network
        logger.warning("Failed to send admin notification: %s", exc)
        return False

    logger.info("Sent admin notification for %s", email)
    return True


def send_user_email(
    to_email: str,
    subject: str,
    body: str,
    *,
    secrets: Any | None = None,
) -> bool:
    """Send a transactional email to an arbitrary recipient.

    Uses the same SMTP credentials as ``send_admin_notification`` but
    routes the message to the caller-supplied ``to_email`` rather than
    the admin address. Used for delivering auto-generated trial tokens
    to premium-request submitters.

    Args:
        to_email: Recipient email address.
        subject: Email subject line.
        body: Plain-text body.
        secrets: Streamlit-secrets-shaped mapping; when ``None`` the
            function attempts to read ``st.secrets`` and falls back to
            no-op if Streamlit isn't running.

    Returns:
        ``True`` when the email was delivered to the SMTP server,
        ``False`` when SMTP is not configured or sending failed.
    """
    cfg = _load_smtp_config(secrets)
    if cfg is None:
        logger.info("SMTP not configured; skipping user email to %s", to_email)
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["from_email"]
    message["To"] = to_email
    message.set_content(body)

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(message)
    except Exception as exc:  # pragma: no cover - network
        logger.warning("Failed to send user email to %s: %s", to_email, exc)
        return False

    logger.info("Sent user email to %s", to_email)
    return True


def _load_smtp_config(secrets: Any | None) -> dict[str, Any] | None:
    """Return a validated SMTP config dict or ``None`` when unavailable."""
    if secrets is None:
        try:
            import streamlit as st

            secrets = st.secrets
        except Exception:
            return None
    try:
        section = secrets["smtp"]
        host = str(section["host"])
        port = int(section["port"])
        user = str(section["user"])
        password = str(section["password"])
    except (KeyError, TypeError, ValueError):
        return None
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "from_email": str(section.get("from_email") or user),
        "to_email": str(section.get("to_email") or _DEFAULT_TO_EMAIL),
    }


def _format_body(email: str, name: str, reason: str) -> str:
    ts = _dt.datetime.utcnow().isoformat(timespec="seconds")
    return (
        "RemediAX admin notification\n"
        f"Timestamp (UTC): {ts}\n"
        f"Name:            {name}\n"
        f"Email:           {email}\n"
        f"Reason / note:   {reason}\n"
    )
