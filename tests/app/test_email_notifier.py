"""Tests for the SMTP admin notifier — smtplib fully mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from database.email_notifier import send_admin_notification, send_user_email


_SECRETS = {
    "smtp": {
        "host": "smtp.example.com",
        "port": 587,
        "user": "noreply@example.com",
        "password": "app-pwd",
        "from_email": "noreply@example.com",
        "to_email": "admin@example.com",
    }
}


def test_send_returns_false_when_secrets_missing() -> None:
    assert send_admin_notification(
        email="a@b.com", name="A", reason="r", secrets={}
    ) is False


def test_send_returns_false_when_smtp_section_partial() -> None:
    assert send_admin_notification(
        email="a@b.com", name="A", reason="r", secrets={"smtp": {"host": "x"}}
    ) is False


def test_send_invokes_smtp_with_message() -> None:
    smtp_mock = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_mock
    smtp_cm.__exit__.return_value = False
    with patch("database.email_notifier.smtplib.SMTP", return_value=smtp_cm) as smtp_class:
        result = send_admin_notification(
            email="alice@example.com",
            name="Alice",
            reason="new signup",
            secrets=_SECRETS,
        )
    assert result is True
    smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=10)
    smtp_mock.starttls.assert_called_once()
    smtp_mock.login.assert_called_once_with("noreply@example.com", "app-pwd")
    smtp_mock.send_message.assert_called_once()
    sent = smtp_mock.send_message.call_args.args[0]
    assert sent["From"] == "noreply@example.com"
    assert sent["To"] == "admin@example.com"
    assert "alice@example.com" in sent.get_content()


def test_send_returns_false_on_smtp_exception() -> None:
    with patch(
        "database.email_notifier.smtplib.SMTP",
        side_effect=ConnectionRefusedError("nope"),
    ):
        assert send_admin_notification(
            email="a@b.com", name="A", reason="r", secrets=_SECRETS
        ) is False


def test_default_to_email_used_when_not_in_secrets() -> None:
    secrets = {
        "smtp": {
            "host": "smtp.example.com",
            "port": 587,
            "user": "noreply@example.com",
            "password": "x",
            # no to_email
        }
    }
    smtp_mock = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_mock
    smtp_cm.__exit__.return_value = False
    with patch("database.email_notifier.smtplib.SMTP", return_value=smtp_cm):
        send_admin_notification(
            email="a@b.com", name="A", reason="r", secrets=secrets
        )
    sent = smtp_mock.send_message.call_args.args[0]
    assert sent["To"] == "nileshvary@gmail.com"


def test_custom_subject() -> None:
    smtp_mock = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_mock
    smtp_cm.__exit__.return_value = False
    with patch("database.email_notifier.smtplib.SMTP", return_value=smtp_cm):
        send_admin_notification(
            email="a@b.com",
            name="A",
            reason="r",
            secrets=_SECRETS,
            subject="[RemediAX] Special",
        )
    sent = smtp_mock.send_message.call_args.args[0]
    assert sent["Subject"] == "[RemediAX] Special"


# ---------------------------------------------------------------------------
# send_user_email — trial-token delivery to the requesting user
# ---------------------------------------------------------------------------


def test_send_user_email_returns_false_when_secrets_missing() -> None:
    assert send_user_email(
        to_email="user@example.com",
        subject="Token",
        body="hello",
        secrets={},
    ) is False


def test_send_user_email_returns_false_when_smtp_section_partial() -> None:
    assert send_user_email(
        to_email="user@example.com",
        subject="Token",
        body="hello",
        secrets={"smtp": {"host": "x"}},
    ) is False


def test_send_user_email_routes_to_recipient_not_admin() -> None:
    smtp_mock = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_mock
    smtp_cm.__exit__.return_value = False
    with patch("database.email_notifier.smtplib.SMTP", return_value=smtp_cm) as smtp_class:
        result = send_user_email(
            to_email="user@example.com",
            subject="Your RemediAX 7-day trial token",
            body="Hi there,\n\n    RMX-abc\n",
            secrets=_SECRETS,
        )
    assert result is True
    smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=10)
    smtp_mock.starttls.assert_called_once()
    smtp_mock.login.assert_called_once_with("noreply@example.com", "app-pwd")
    sent = smtp_mock.send_message.call_args.args[0]
    assert sent["From"] == "noreply@example.com"
    assert sent["To"] == "user@example.com"
    assert sent["To"] != "admin@example.com"
    assert sent["Subject"] == "Your RemediAX 7-day trial token"
    assert "RMX-abc" in sent.get_content()


def test_send_user_email_returns_false_on_smtp_exception() -> None:
    with patch(
        "database.email_notifier.smtplib.SMTP",
        side_effect=ConnectionRefusedError("nope"),
    ):
        assert send_user_email(
            to_email="user@example.com",
            subject="Token",
            body="x",
            secrets=_SECRETS,
        ) is False
