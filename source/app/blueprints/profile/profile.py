# profile.py — theme switcher endpoint
# Добавляет /profile/theme к endpoint для смены темы через AJAX.
# Файл дополняет существующий profile blueprint.
import logging
from flask import Blueprint, request, jsonify
from flask_login import current_user, login_required

from app import db

log = logging.getLogger(__name__)

profile_theme_bp = Blueprint('profile_theme', __name__)

ALLOWED_THEMES = {'light', 'dark', 'pride'}


@profile_theme_bp.route('/profile/theme', methods=['POST'])
@login_required
def set_theme():
    """POST /profile/theme  {"theme": "pride|dark|light"}"""
    data = request.get_json(silent=True) or {}
    theme = data.get('theme', '').strip().lower()

    if theme not in ALLOWED_THEMES:
        return jsonify({'status': 'error', 'message': 'Invalid theme'}), 400

    current_user.user_theme = theme
    # Keep legacy field in sync
    current_user.in_dark_mode = (theme == 'dark')
    db.session.commit()

    log.info('User %s switched theme to %s', current_user.user, theme)
    return jsonify({'status': 'success', 'theme': theme})
