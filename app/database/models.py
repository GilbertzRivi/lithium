from sqlalchemy import Column, String, DateTime, func, LargeBinary, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from passlib import pwd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from base64 import b64encode, b64decode
import uuid

# Importing the Base from session.py
from .session import Base

# Password hashing context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Constants for AES encryption
KEY_SIZE = 32  # AES-256
IV_SIZE = 16  # 128-bit IV
BLOCK_SIZE = 128  # AES block size


# User model
class User(Base):
    __tablename__ = "users"

    id = Column(UUID, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    aes_salt = Column(LargeBinary, nullable=False)
    handler = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    public_key = Column(LargeBinary, nullable=False)
    private_key = Column(LargeBinary, nullable=False)
    single_use_token = Column(String, nullable=True)

    messages_sent = relationship(
        "Message", back_populates="sender", foreign_keys="[Message.sender_id]"
    )
    messages_received = relationship(
        "Message", back_populates="recepient", foreign_keys="[Message.recepient_id]"
    )

    def set_password(self, password: str):
        """
        Hashes the password using a generated salt.
        """
        self.salt = pwd.genword(entropy=128, length=16)  # Generate a 16-character salt
        password_with_salt = password + self.salt
        self.password_hash = pwd_context.hash(password_with_salt)

    def verify_password(self, password: str) -> bool:
        """
        Verifies the password by checking the hash with the stored salt.
        """
        password_with_salt = password + self.salt
        return pwd_context.verify(password_with_salt, self.password_hash)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a cryptographic key from the password using PBKDF2. If salt is not provided, generates a new one.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypts the provided data using AES-256 in CBC mode with PKCS7 padding.
        """
        iv = os.urandom(IV_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding the data
        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return b64encode(
            iv + encrypted_data
        )  # Return IV + encrypted data (base64 encoded)

    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts AES-256 encrypted data.
        """
        encrypted_data = b64decode(encrypted_data)
        iv = encrypted_data[:IV_SIZE]
        encrypted_content = encrypted_data[IV_SIZE:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = (
            decryptor.update(encrypted_content) + decryptor.finalize()
        )

        # Remove padding
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return data

    def generate_keys(self, password: str):
        """
        Generates RSA public and private keys, encrypts the private key, and stores both in the model.
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Derive AES key from password
        self.aes_salt = os.urandom(16)
        aes_key = self._derive_key(password, self.aes_salt)

        # Encrypt private key using AES
        encrypted_private_key = self._encrypt_data(private_key_bytes, aes_key)

        # Store public key (in plaintext) and private key (encrypted)
        self.public_key = public_key_bytes
        self.private_key = encrypted_private_key

    def get_private_key(self, password: str) -> bytes:
        """
        Decrypts and retrieves the user's private key using the provided password.
        """
        # Derive AES key from password
        aes_key = self._derive_key(password, self.aes_salt)

        # Decrypt and return private key
        decrypted_private_key = self._decrypt_data(self.private_key, aes_key)
        return decrypted_private_key


class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    token = Column(String, nullable=False)
    valid = Column(Boolean, default=True)

    def invalidate(self):
        self.valid = False


class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    content = Column(LargeBinary, nullable=False)
    recepient_id = Column(UUID, ForeignKey("users.id"))
    sender_id = Column(UUID, ForeignKey("users.id"))

    recepient = relationship(
        "User", back_populates="messages_received", foreign_keys=[recepient_id]
    )
    sender = relationship(
        "User", back_populates="messages_sent", foreign_keys=[sender_id]
    )
