import bcrypt
from app.models.models import User
from app.database.connection import db
from app.encryption.rsa_engine import generate_rsa_keypair

def bootstrap_admin(app):
    """
    Idempotently seeds the database with the initial admin user using settings configured in the env.
    Does not overwrite if an admin already exists.
    """
    with app.app_context():
        # Check if an administrator already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            return

        admin_email = app.config.get('ADMIN_EMAIL')
        admin_password = app.config.get('ADMIN_PASSWORD')

        if not admin_email or not admin_password:
            return

        # Generate RSA keypair for administrator asymmetric cryptography
        private_pem, public_pem = generate_rsa_keypair(2048)

        # Hash passphrase using bcrypt
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        admin_user = User(
            full_name="System Administrator",
            email=admin_email,
            password_hash=password_hash,
            role='admin',
            status='active',
            rsa_public_key=public_pem.decode('utf-8'),
            rsa_private_key=private_pem.decode('utf-8')
        )
        db.session.add(admin_user)
        db.session.commit()
