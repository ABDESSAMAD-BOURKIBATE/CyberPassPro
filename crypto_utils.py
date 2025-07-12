from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import logging
import shutil
import base64
import secrets

# إعداد التسجيل (Logging) مع تنسيق موحد
logging.basicConfig(
    filename='crypto_utils.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

class CryptoUtils:
    """فئة لإدارة عمليات التشفير وفك التشفير باستخدام Fernet بناءً على كلمة سر المستخدم."""

    def __init__(self, user_folder):
        """
        تهيئة CryptoUtils مع مجلد بيانات المستخدم.
        
        Args:
            user_folder (str): مسار مجلد بيانات المستخدم.
        """
        self.user_folder = user_folder
        self.key_path = os.path.join(user_folder, "master.key")
        self.backup_key_path = os.path.join(user_folder, "master_backup.key")
        self.salt_path = os.path.join(user_folder, "salt.key")
        self.fernet = None
        os.makedirs(user_folder, exist_ok=True)

    def _derive_key(self, password: bytes, salt: bytes = None):
        """
        اشتقاق مفتاح تشفير آمن باستخدام PBKDF2 مع كلمة السر والملح.
        
        Args:
            password (bytes): كلمة السر المستخدمة في الاشتقاق.
            salt (bytes, optional): الملح المستخدم في الاشتقاق. إذا لم يُحدد، يتم إنشاء ملح جديد.
            
        Returns:
            bytes: مفتاح Fernet مشفر.
        """
        if salt is None:
            salt = secrets.token_bytes(16)
            with open(self.salt_path, "wb") as f:
                f.write(salt)
        else:
            if not os.path.exists(self.salt_path):
                with open(self.salt_path, "wb") as f:
                    f.write(salt)
            else:
                with open(self.salt_path, "rb") as f:
                    salt = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def get_user_key(self, password: str):
        """
        استرجاع أو إنشاء مفتاح تشفير للمستخدم باستخدام كلمة السر.
        
        Args:
            password (str): كلمة سر المستخدم.
            
        Returns:
            Fernet: كائن Fernet للتشفير/فك التشفير.
        """
        try:
            password_bytes = password.encode('utf-8')

            if not os.path.exists(self.key_path):
                # لم يتم العثور على مفتاح - اشتقاق جديد وحفظه
                key = self._derive_key(password_bytes)
                with open(self.key_path, "wb") as f:
                    f.write(key)
                # إنشاء نسخة احتياطية
                shutil.copy(self.key_path, self.backup_key_path)
                logging.info(f"تم إنشاء مفتاح جديد للمستخدم وحفظه في {self.user_folder}")
            else:
                # قراءة المفتاح الموجود
                with open(self.key_path, "rb") as f:
                    key = f.read()

            self.fernet = Fernet(key)
            return self.fernet
        except Exception as e:
            logging.error(f"فشل في استرجاع/إنشاء المفتاح: {str(e)}")
            raise

    def encrypt_message(self, message: str):
        """
        تشفير رسالة باستخدام مفتاح Fernet.
        
        Args:
            message (str): النص المراد تشفيره.
            
        Returns:
            bytes: النص المشفر.
        """
        if self.fernet is None:
            raise ValueError("المفتاح غير مهيأ. يرجى استدعاء get_user_key أولاً.")
        try:
            encrypted = self.fernet.encrypt(message.encode('utf-8'))
            logging.info("تم تشفير رسالة بنجاح")
            return encrypted
        except Exception as e:
            logging.error(f"فشل في تشفير الرسالة: {str(e)}")
            raise

    def decrypt_message(self, token: bytes):
        """
        فك تشفير رسالة باستخدام مفتاح Fernet.
        
        Args:
            token (bytes): النص المشفر.
            
        Returns:
            str: النص المفكوك.
        """
        if self.fernet is None:
            raise ValueError("المفتاح غير مهيأ. يرجى استدعاء get_user_key أولاً.")
        try:
            decrypted = self.fernet.decrypt(token).decode('utf-8')
            logging.info("تم فك تشفير رسالة بنجاح")
            return decrypted
        except InvalidToken:
            logging.error("فشل فك التشفير: رمز غير صالح")
            raise ValueError("رمز التشفير غير صالح")
        except Exception as e:
            logging.error(f"فشل في فك تشفير الرسالة: {str(e)}")
            raise
