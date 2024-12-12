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
    handler = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    public_key = Column(LargeBinary, nullable=False)
    single_use_token = Column(String, nullable=True)
    pfp = Column(LargeBinary, nullable=True)

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
