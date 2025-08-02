# from sqlalchemy import Column, Integer, String
# from sqlalchemy.ext.declarative import declarative_base

# Base = declarative_base()

# class User(Base):  # <-- Must match the import name
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String, unique=True, index=True)
#     email = Column(String, unique=True, index=True)
#     hashed_password = Column(String)

# from sqlalchemy import Column, Integer, String, Boolean
# from sqlalchemy.ext.declarative import declarative_base

# Base = declarative_base()

# class User(Base):
#     __tablename__ = 'users'
    
#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String(50), unique=True, nullable=False)  # Username (unique)
#     email = Column(String(100), unique=True, nullable=False)   # Email (optional)
#     hashed_password = Column(String(100), nullable=False)      # Hashed Password
#     is_active = Column(Boolean, default=True)                 # Account Status

# from sqlalchemy import Column, Integer, String, Boolean, DateTime
# from sqlalchemy.ext.declarative import declarative_base
# from datetime import datetime

# Base = declarative_base()

# class User(Base):
#     __tablename__ = 'users'
    
#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String(50), unique=True, nullable=False)
#     email = Column(String(100), unique=True, nullable=True)  # Optional email
#     hashed_password = Column(String(255), nullable=False)    # Longer for hashes
#     is_active = Column(Boolean, default=True)
#     created_at = Column(DateTime, default=datetime.utcnow)   # Auto-set on create
#     updated_at = Column(DateTime, onupdate=datetime.utcnow)  # Auto-update


from sqlalchemy import Column, Integer, String
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
