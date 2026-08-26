from flask import Blueprint
from app.utils.auth_middleware import token_required, admin_required
from app.controllers.api_controller import (
    register_user,
    login_user,
    admin_login_user,
    encrypt_endpoint,
    decrypt_endpoint,
    classify_text,
    get_classification_history,
    upload_file_endpoint,
    share_file_key,
    get_dashboard_summary,
    get_activity_logs,
    get_user_profile,
    keys_generate,
    keys_current,
    download_file_encrypted,
    download_file_decrypted,
    generate_hash_endpoint,
    verify_file_endpoint,
    share_file_endpoint,
    resolve_shared_link,
    download_shared_file,
    revoke_shared_link,
    get_shared_history,
    get_security_alerts_endpoint,
    get_statistics_endpoint,
    logout_endpoint,
    get_users_list,
    resolve_security_alert_endpoint
)

api_bp = Blueprint('api', __name__)

# Authentication (Unsecured)
api_bp.route('/register', methods=['POST'])(register_user)
api_bp.route('/login', methods=['POST'])(login_user)
api_bp.route('/admin/login', methods=['POST'])(admin_login_user)
api_bp.route('/logout', methods=['POST'])(token_required(logout_endpoint))

# Admin actions
api_bp.route('/admin/users', methods=['GET'])(token_required(admin_required(get_users_list)))
api_bp.route('/admin/alerts/<int:alert_id>/resolve', methods=['POST'])(token_required(admin_required(resolve_security_alert_endpoint)))

@api_bp.route('/admin/dashboard', methods=['GET'])
@token_required
@admin_required
def get_admin_dashboard_summary(current_user):
    return get_dashboard_summary(current_user)

# Cryptography endpoints (Secured)
api_bp.route('/encrypt', methods=['POST'])(token_required(encrypt_endpoint))
api_bp.route('/decrypt', methods=['POST'])(token_required(decrypt_endpoint))
api_bp.route('/keys/current', methods=['GET'])(token_required(keys_current))
api_bp.route('/keys/generate', methods=['GET'])(token_required(keys_generate))

# DLP text scan & file vault uploads (Secured)
api_bp.route('/classify', methods=['POST'])(token_required(classify_text))
api_bp.route('/classify/history', methods=['GET'])(token_required(get_classification_history))
api_bp.route('/upload', methods=['POST'])(token_required(upload_file_endpoint))
api_bp.route('/files/<int:file_id>/download/encrypted', methods=['GET'])(token_required(download_file_encrypted))
api_bp.route('/files/<int:file_id>/download/decrypted', methods=['POST'])(token_required(download_file_decrypted))

# File Integrity & Sharing (Secured/Public)
api_bp.route('/generate-hash', methods=['POST'])(token_required(generate_hash_endpoint))
api_bp.route('/verify-file', methods=['POST'])(token_required(verify_file_endpoint))
api_bp.route('/share-file', methods=['POST'])(token_required(share_file_endpoint))
api_bp.route('/shared/<string:token>', methods=['GET'])(resolve_shared_link)
api_bp.route('/shared/<string:token>/download', methods=['POST'])(download_shared_file)
api_bp.route('/share/<int:share_id>', methods=['DELETE'])(token_required(revoke_shared_link))
api_bp.route('/share/history', methods=['GET'])(token_required(get_shared_history))

# File delegation sharing (Secured)
api_bp.route('/share', methods=['POST'])(token_required(share_file_key))

# Monitoring & queries (Secured)
api_bp.route('/dashboard', methods=['GET'])(token_required(get_dashboard_summary))
api_bp.route('/logs', methods=['GET'])(token_required(get_activity_logs))
api_bp.route('/profile', methods=['GET'])(token_required(get_user_profile))
api_bp.route('/security-alerts', methods=['GET'])(token_required(get_security_alerts_endpoint))
api_bp.route('/statistics', methods=['GET'])(token_required(get_statistics_endpoint))


