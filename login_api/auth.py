# # login_api/auth.py
# from passlib.context import CryptContext
# from datetime import datetime, timedelta
# from jose import jwt
# from typing import Optional

# # Password hashing setup
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # JWT configuration
# SECRET_KEY = "your-secret-key-here"  # प्रोडक्शन में इसे सुरक्षित रखें
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# def get_password_hash(password: str) -> str:
#     """Generate password hash"""
#     return pwd_context.hash(password)

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     """Verify password against hash"""
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     """Create JWT token"""
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    

# # टोकन से यूजर डिकोड करने का फंक्शन
# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
    
#     # यहां डेटाबेस से यूजर फेच करें
#     user = await get_user_from_db(username)  # अपना डेटाबेस फंक्शन यहां लगाएं
#     if user is None:
#         raise credentials_exception
#     return user


# D:\python_live_api\login_api\auth.py
# from passlib.context import CryptContext
# from datetime import datetime, timedelta
# from jose import jwt, JWTError
# from typing import Optional
# from fastapi import HTTPException, status, Depends  # Depends यहाँ जोड़ा गया है
# from fastapi.security import OAuth2PasswordBearer

# # Password hashing setup
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # JWT configuration
# SECRET_KEY = "your-secret-key-here"  # प्रोडक्शन में इसे सुरक्षित रखें
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # OAuth2 scheme
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# def get_password_hash(password: str) -> str:
#     """Generate password hash"""
#     return pwd_context.hash(password)

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     """Verify password against hash"""
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     """Create JWT token"""
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         return {"username": username}  # Temporary response
#     except JWTError:
#         raise credentials_exception

from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extract user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        return {"username": username}
    except JWTError:
        raise credentials_exception
