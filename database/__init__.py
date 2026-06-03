"""RemediAX database layer: Firebase Auth + Firestore + SMTP notifier."""

from database.email_notifier import send_admin_notification, send_user_email
from database.firebase_manager import (
    FirebaseAuthError,
    create_user,
    get_all_scans,
    get_init_error,
    get_user,
    get_user_scans,
    get_user_tier,
    init_firebase,
    is_firebase_ready,
    login_user,
    save_scan,
    save_token_request,
    scans_this_month,
    set_user_tier,
    update_scan,
)

__all__ = [
    "FirebaseAuthError",
    "create_user",
    "get_all_scans",
    "get_init_error",
    "get_user",
    "get_user_scans",
    "get_user_tier",
    "init_firebase",
    "is_firebase_ready",
    "login_user",
    "save_scan",
    "save_token_request",
    "scans_this_month",
    "send_admin_notification",
    "send_user_email",
    "set_user_tier",
    "update_scan",
]
