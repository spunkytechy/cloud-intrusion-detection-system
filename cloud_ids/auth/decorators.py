"""auth/decorators.py - Role-based access control decorators."""
from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(f):
    """Restrict route to admin users only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    """Restrict route to analyst or admin users."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_analyst():
            abort(403)
        return f(*args, **kwargs)
    return decorated
