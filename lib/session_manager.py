from flask import redirect, url_for
import time


# Enforce session timeout based on inactivity and absolute time limits
def enforce_session_timeout(session, session_time_minutes, inactivity_seconds):
    if 'authorized' not in session:
        return None
    
    now = int(time.time())
    last = session.get("last_activity", now)
    start = session.get("session_start", now)

    # Get user's auto-lock preference, default to provided inactivity seconds
    user_timeout = session.get('auto_lock_timeout', inactivity_seconds)

    # Check if idle timeout or absolute timeout exceeded
    if (now - last) > user_timeout or (now - start) > (session_time_minutes * 60):
        session.clear()
        return redirect(url_for("login"))

    # Update last activity timestamp
    session["last_activity"] = now
    session.setdefault("session_start", now)
    return None
