import unittest
import os
import sys
import tempfile
import shutil
import json
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, FileSharing, FileClassification, FileIntegrity, ActivityLog, SecurityAlert, EncryptionKey
from app.utils.auth_middleware import encode_auth_token
from app.controllers.api_controller import trigger_security_alert

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-321'
    JWT_SECRET = 'test-jwt-secret-321'
    ADMIN_EMAIL = 'admin_bootstrap@cipherguard.test'
    ADMIN_PASSWORD = 'BootstrapPassword123!'

class TestCipherGuardAlertsNotifications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.app = create_app(TestConfig)
        cls.app.instance_path = cls.temp_dir
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        db.session.remove()
        db.drop_all()
        db.create_all()

        self.client = self.app.test_client()

        # Seed password hash for standard tests
        self.plain_password = "Password123!"
        self.hashed_password = bcrypt.hashpw(self.plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create Admin
        self.admin = User(
            full_name="System Admin",
            email="admin@cipherguard.test",
            password_hash=self.hashed_password,
            role="admin",
            status="active"
        )
        db.session.add(self.admin)

        # Create User A
        self.user_a = User(
            full_name="User A",
            email="usera@cipherguard.test",
            password_hash=self.hashed_password,
            role="user",
            status="active"
        )
        db.session.add(self.user_a)

        # Create User B
        self.user_b = User(
            full_name="User B",
            email="userb@cipherguard.test",
            password_hash=self.hashed_password,
            role="user",
            status="active"
        )
        db.session.add(self.user_b)
        db.session.commit()

        # Tokens
        self.admin_token = encode_auth_token(self.admin.id)
        self.usera_token = encode_auth_token(self.user_a.id)
        self.userb_token = encode_auth_token(self.user_b.id)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    # ==========================================
    # USER NOTIFICATION TESTS
    # ==========================================

    def test_user_receives_own_notification(self):
        # 1. User A receives their own security notification
        alert = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Security Alert',
            severity='LOW',
            message='Your file was shared',
            category='SHARING',
            target_role='user'
        )
        
        res = self.client.get("/api/notifications", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["unread_count"], 1)
        self.assertEqual(len(data["notifications"]), 1)
        self.assertEqual(data["notifications"][0]["message"], 'Your file was shared')

    def test_user_cannot_see_another_user_notification(self):
        # 2. User B cannot see User A's notifications
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Security Alert',
            severity='LOW',
            message='User A specific message',
            category='SHARING',
            target_role='user'
        )
        
        res = self.client.get("/api/notifications", headers={"Authorization": f"Bearer {self.userb_token}"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["unread_count"], 0)
        self.assertEqual(len(data["notifications"]), 0)

    def test_user_can_mark_notification_read(self):
        # 3. User can mark notification as read
        alert = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Security Alert',
            severity='LOW',
            message='Test message',
            category='SHARING',
            target_role='user'
        )
        
        res = self.client.patch(f"/api/notifications/{alert.id}/read", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 200)
        
        # Verify unread count is 0
        res_count = self.client.get("/api/notifications/unread-count", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(json.loads(res_count.data)["unread_count"], 0)

    def test_user_can_mark_all_notifications_read(self):
        # 4. User can mark all notifications as read
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Alert 1',
            severity='LOW',
            message='Msg 1',
            category='SHARING',
            target_role='user'
        )
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Alert 2',
            severity='LOW',
            message='Msg 2',
            category='SHARING',
            target_role='user'
        )
        
        res = self.client.patch("/api/notifications/read-all", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 200)
        
        res_count = self.client.get("/api/notifications/unread-count", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(json.loads(res_count.data)["unread_count"], 0)

    # ==========================================
    # ADMIN SECURITY ALERTS TESTS
    # ==========================================

    def test_admin_receives_system_wide_alert(self):
        # 7. Admin receives system-wide security alert
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Privilege escalation',
            severity='CRITICAL',
            message='Attempted role manipulation',
            category='ACCOUNT_SECURITY',
            target_role='admin'
        )
        
        res = self.client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["alert_type"], 'Privilege escalation')

    def test_admin_can_filter_alerts(self):
        # 9. Admin can filter alerts by severity and category
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Alert A',
            severity='CRITICAL',
            message='Critical event',
            category='ACCOUNT_SECURITY',
            target_role='admin'
        )
        trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Alert B',
            severity='LOW',
            message='Low event',
            category='SHARING',
            target_role='admin'
        )
        
        # Filter by CRITICAL
        res_crit = self.client.get("/api/admin/alerts?severity=CRITICAL", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(len(json.loads(res_crit.data)), 1)
        
        # Filter by SHARING
        res_sharing = self.client.get("/api/admin/alerts?category=SHARING", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(len(json.loads(res_sharing.data)), 1)

    def test_admin_can_resolve_alerts(self):
        # 11. Admin can resolve alerts
        alert = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Alert',
            severity='CRITICAL',
            message='Critical alert to resolve',
            category='ACCOUNT_SECURITY',
            target_role='admin'
        )
        
        res = self.client.patch(f"/api/admin/alerts/{alert.id}/resolve", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res.status_code, 200)
        
        # Verify status is resolved
        db.session.refresh(alert)
        self.assertEqual(alert.status, 'resolved')
        self.assertEqual(alert.resolved_by, self.admin.id)

    # ==========================================
    # ACCESS CONTROL & SECURITY BOUNDARIES
    # ==========================================

    def test_unauthenticated_receives_401(self):
        # 13. Unauthenticated user receives 401
        res = self.client.get("/api/notifications")
        self.assertEqual(res.status_code, 401)
        
        res_admin = self.client.get("/api/admin/alerts")
        self.assertEqual(res_admin.status_code, 401)

    def test_normal_user_receives_403_on_admin_apis(self):
        # 14. Normal user receives 403 on admin alert APIs
        res = self.client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 403)

    def test_user_cannot_modify_another_user_notification(self):
        # 15. User B cannot mark User A's notification as read (IDOR prevention)
        alert = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='User A Alert',
            severity='LOW',
            message='Private Alert',
            category='SHARING',
            target_role='user'
        )
        
        res = self.client.patch(f"/api/notifications/{alert.id}/read", headers={"Authorization": f"Bearer {self.userb_token}"})
        self.assertEqual(res.status_code, 403)

    def test_user_cannot_resolve_admin_alerts(self):
        # 16. User cannot resolve admin alerts
        alert = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Admin Alarm',
            severity='CRITICAL',
            message='Admin Alarm details',
            category='ACCOUNT_SECURITY',
            target_role='admin'
        )
        
        res = self.client.patch(f"/api/admin/alerts/{alert.id}/resolve", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 403)

    # ==========================================
    # NOTIFICATION DEDUPLICATION
    # ==========================================

    def test_repeated_events_deduplication(self):
        # 24. Repeated identical events within 5 minutes do not cause uncontrolled alert spam
        # Trigger same alert twice
        alert1 = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Spam Alert',
            severity='MEDIUM',
            message='Repeated event message',
            category='SHARING',
            target_role='user'
        )
        
        alert2 = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Spam Alert',
            severity='MEDIUM',
            message='Repeated event message',
            category='SHARING',
            target_role='user'
        )
        
        # Verify they resolved to the same database row/object (deduplicated)
        self.assertEqual(alert1.id, alert2.id)
        
        # Total security alerts in database for this type should be 1
        count = SecurityAlert.query.filter_by(user_id=self.user_a.id, alert_type='Spam Alert').count()
        self.assertEqual(count, 1)

    # ==========================================
    # ALERT GENERATION & INTEGRATION TESTS
    # ==========================================

    def test_file_integrity_violating_alerts(self):
        # 5. User receives appropriate file-integrity alert on tampering
        # 19. Integrity tampering generates appropriate alert
        alert_user = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='File tampering detected',
            severity='CRITICAL',
            message='Integrity mismatch on file A',
            category='INTEGRITY',
            target_role='user'
        )
        alert_admin = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='File tampering detected',
            severity='CRITICAL',
            message='CRITICAL: Integrity signature mismatch on file A',
            category='INTEGRITY',
            target_role='admin',
            event_type='FILE_TAMPERING'
        )
        self.assertEqual(alert_user.category, 'INTEGRITY')
        self.assertEqual(alert_admin.event_type, 'FILE_TAMPERING')

    def test_account_lockout_alerts(self):
        # 6. User receives account-security alert
        # 20. Account lockout generates appropriate alert
        alert_user = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Multiple failed login attempts',
            severity='HIGH',
            message='Operator account locked due to 3 consecutive failures.',
            category='AUTHENTICATION',
            target_role='user'
        )
        alert_admin = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Multiple failed login attempts',
            severity='HIGH',
            message='Operator account locked: usera@cipherguard.test locked.',
            category='AUTHENTICATION',
            target_role='admin',
            event_type='ACCOUNT_LOCKOUT'
        )
        self.assertEqual(alert_user.category, 'AUTHENTICATION')
        self.assertEqual(alert_admin.event_type, 'ACCOUNT_LOCKOUT')

    def test_unauthorized_admin_access_alert(self):
        # 21. Unauthorized admin access generates appropriate alert
        alert_admin = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Unauthorized admin access',
            severity='HIGH',
            message='Operator usera@cipherguard.test attempted unauthorized access.',
            category='ACCOUNT_SECURITY',
            target_role='admin',
            event_type='UNAUTHORIZED_ADMIN_ACCESS'
        )
        self.assertEqual(alert_admin.event_type, 'UNAUTHORIZED_ADMIN_ACCESS')
        self.assertEqual(alert_admin.target_role, 'admin')

    def test_sensitive_file_classification_notification(self):
        # 22. Sensitive file classification generates appropriate user notification
        alert_user = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='File classification warning',
            severity='MEDIUM',
            message='DLP Warning: File test.txt classified as Secret.',
            category='AI_CLASSIFICATION',
            target_role='user'
        )
        self.assertEqual(alert_user.category, 'AI_CLASSIFICATION')
        self.assertEqual(alert_user.target_role, 'user')

    def test_share_expiration_notification(self):
        # 23. Share expiration generates appropriate notification
        alert_user = trigger_security_alert(
            user_id=self.user_a.id,
            alert_type='Share link expired',
            severity='LOW',
            message='A secure share link for test.txt has expired.',
            category='SHARING',
            target_role='user'
        )
        self.assertEqual(alert_user.category, 'SHARING')
        self.assertEqual(alert_user.target_role, 'user')

if __name__ == '__main__':
    unittest.main()
