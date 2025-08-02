# from fastapi import FastAPI

# app = FastAPI()

# @app.get("/")
# def read_root():
#     return {"message": "omkar, FastAPI is working!"}

# from fastapi import FastAPI, Depends, HTTPException
# from sqlalchemy.orm import Session
# from .models import User            # <-- relative import
# from .database import SessionLocal, engine, Base  # <-- relative import
# from login_api.models import User

# Base.metadata.create_all(bind=engine)

# app = FastAPI()

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.get("/")
# def read_root():
#     return {"message": "Hello, FastAPI is working!"}

# @app.post("/register")
# def register_user(username: str, password: str, db: Session = Depends(get_db)):
#     user = User(username=username, password=password)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return {"message": "User registered", "user_id": user.id}

# @app.post("/login")
# def login_user(username: str, password: str, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.username == username).first()
#     if not user or user.password != password:
#         raise HTTPException(status_code=401, detail="Invalid username or password")
#     return {"message": "Login successful"}


# from fastapi import FastAPI, Depends, HTTPException

# # सही (रिलेटिव इम्पोर्ट हटाएं):
# from login_api.auth import get_password_hash, verify_password
# from .auth import (
#     get_password_hash,
#     verify_password,
#     create_access_token,
#     get_current_user,
#     oauth2_scheme
# )
# from .models import User
# from datetime import timedelta
# from fastapi import FastAPI, Depends, HTTPException
# from login_api.auth import get_password_hash, verify_password
# from login_api.models import User

# app = FastAPI()

# # डमी डेटाबेस (असली एप्लिकेशन में डेटाबेस का उपयोग करें)
# fake_users_db = {
#     "john": {
#         "username": "john",
#         "hashed_password": get_password_hash("secret123"),
#         "disabled": False,
#     }
# }

# # यूजर रजिस्ट्रेशन
# @app.post("/register")
# async def register(username: str, password: str):
#     if username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Username already registered")
    
#     hashed_password = get_password_hash(password)
#     fake_users_db[username] = {
#         "username": username,
#         "hashed_password": hashed_password,
#         "disabled": False,
#     }
#     return {"message": "User created successfully"}

# # लॉगिन और टोकन जनरेशन
# @app.post("/token")
# async def login_for_access_token(username: str, password: str):
#     user = fake_users_db.get(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
    
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user["username"]}, expires_delta=access_token_expires
#     )
#     return {"access_token": access_token, "token_type": "bearer"}

# # प्रोटेक्टेड रूट
# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_user)):
#     return current_user

# from fastapi import FastAPI, Depends, HTTPException, status
# from sqlalchemy.orm import Session
# from datetime import timedelta

# from login_api.auth import (
#     get_password_hash,
#     verify_password,
#     create_access_token,
#     get_current_user,
#     oauth2_scheme,
#     ACCESS_TOKEN_EXPIRE_MINUTES
# )
# from login_api.models import User
# from login_api.database import SessionLocal

# app = FastAPI()

# # ---- Fake DB for demo ----
# fake_users_db = {
#     "john": {
#         "username": "john",
#         "hashed_password": get_password_hash("secret123"),
#         "disabled": False,
#     }
# }

# # ---- Dependency to get DB Session ----
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# # ---- Register User ----
# @app.post("/register")
# async def register(username: str, password: str):
#     if username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Username already registered")

#     hashed_password = get_password_hash(password)
#     fake_users_db[username] = {
#         "username": username,
#         "hashed_password": hashed_password,
#         "disabled": False,
#     }
#     return {"message": "User created successfully"}

# # ---- Login and Token ----
# @app.post("/token")
# async def login_for_access_token(username: str, password: str):
#     user = fake_users_db.get(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user["username"]},
#         expires_delta=access_token_expires
#     )

#     return {"access_token": access_token, "token_type": "bearer"}

# # ---- Protected Route ----
# @app.get("/users/me")
# async def read_users_me(current_user: dict = Depends(get_current_user)):
#     return current_user


# from fastapi import FastAPI, Depends, HTTPException, Form, status
# from datetime import timedelta
# from login_api.auth import (
#     get_password_hash,
#     verify_password,
#     create_access_token,
#     get_current_user,
#     oauth2_scheme
# )
# from login_api.models import User

# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# app = FastAPI()

# # ---- Fake DB ----
# fake_users_db = {}

# @app.post("/register")
# async def register(username: str = Form(...), password: str = Form(...)):
#     if username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Username already registered")

#     hashed_password = get_password_hash(password)
#     fake_users_db[username] = {
#         "username": username,
#         "hashed_password": hashed_password,
#         "disabled": False,
#     }
#     return {"message": f"User '{username}' created successfully"}

# @app.post("/token")
# async def login_for_access_token(
#     username: str = Form(...),
#     password: str = Form(...)
# ):
#     user = fake_users_db.get(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user["username"]}, 
#         expires_delta=access_token_expires
#     )

#     return {"access_token": access_token, "token_type": "bearer"}

# @app.get("/users/me")
# async def read_users_me(current_user: dict = Depends(get_current_user)):
#     return current_user


# from fastapi import FastAPI, Depends, HTTPException, status, Form
# from fastapi.security import OAuth2PasswordBearer
# from datetime import timedelta
# from sqlalchemy.orm import Session

# from login_api.auth import (
#     get_password_hash,
#     verify_password,
#     create_access_token,
#     get_current_user,
#     oauth2_scheme,
#     ACCESS_TOKEN_EXPIRE_MINUTES
# )
# from login_api.models import User
# from login_api.database import SessionLocal

# app = FastAPI()

# # Dummy database
# fake_users_db = {}

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.post("/register")
# async def register(username: str = Form(...), password: str = Form(...)):
#     if username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Username already registered")

#     hashed_password = get_password_hash(password)
#     fake_users_db[username] = {
#         "username": username,
#         "hashed_password": hashed_password,
#         "disabled": False,
#     }

#     # Generate token immediately after registration
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": username},
#         expires_delta=access_token_expires
#     )

#     return {
#         "message": f"User '{username}' created successfully",
#         "access_token": access_token,
#         "token_type": "bearer"
#     }

# @app.post("/token")
# async def login_for_access_token(username: str = Form(...), password: str = Form(...)):
#     user = fake_users_db.get(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user["username"]},
#         expires_delta=access_token_expires
#     )

#     return {"access_token": access_token, "token_type": "bearer"}

# @app.get("/users/me")
# async def read_users_me(current_user: dict = Depends(get_current_user)):
#     return current_user


# from fastapi import FastAPI, Depends, HTTPException, status
# from fastapi.security import APIKeyHeader
# from fastapi.openapi.utils import get_openapi
# from jose import JWTError, jwt
# from datetime import datetime, timedelta
# from typing import Optional

# app = FastAPI()

# # ====== Token Config ======
# SECRET_KEY = "your-secret-key-here"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # ====== Swagger Security ======
# token_header = APIKeyHeader(name="Authorization")

# # ====== Dummy Database ======
# fake_users_db = {}

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# async def get_current_user(token: str = Depends(token_header)):
#     if not token.startswith("Bearer "):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
#     token = token.split(" ")[1]
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username = payload.get("sub")
#         if username is None:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
#         return {"username": username}
#     except JWTError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired or invalid")

# @app.post("/register")
# async def register(username: str, password: str):
#     if username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Username already exists")
#     fake_users_db[username] = password
#     token = create_access_token({"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     return {
#         "message": f"User '{username}' created successfully",
#         "access_token": token,
#         "token_type": "bearer"
#     }

# @app.get("/users/me")
# async def read_users_me(current_user: dict = Depends(get_current_user)):
#     return current_user

# # ✅ Custom Swagger UI (Token Paste Field)
# def custom_openapi():
#     if app.openapi_schema:
#         return app.openapi_schema
#     openapi_schema = get_openapi(
#         title="My FastAPI Auth Example",
#         version="1.0.0",
#         description="Swagger UI with Bearer Token Authorization",
#         routes=app.routes,
#     )
#     openapi_schema["components"]["securitySchemes"] = {
#         "BearerAuth": {
#             "type": "http",
#             "scheme": "bearer",
#             "bearerFormat": "JWT"
#         }
#     }
#     for path in openapi_schema["paths"].values():
#         for method in path.values():
#             method["security"] = [{"BearerAuth": []}]
#     app.openapi_schema = openapi_schema
#     return app.openapi_schema

# app.openapi = custom_openapi

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import APIKeyHeader
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# ====== Token Config ======
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ====== Swagger Security ======
token_header = APIKeyHeader(name="Authorization")

# ====== Dummy Database ======
fake_users_db = {}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(token_header)):
    if not token.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
    token = token.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {"username": username}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired or invalid")

# ✅ Register API
@app.post("/register")
async def register(username: str, password: str):
    if username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    fake_users_db[username] = password
    token = create_access_token({"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "message": f"User '{username}' created successfully",
        "access_token": token,
        "token_type": "bearer"
    }

# ✅ Login API
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username not in fake_users_db:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if fake_users_db[username] != password:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token = create_access_token({"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ✅ Protected API
@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

# ✅ Custom Swagger UI (Bearer Token Field)
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="My FastAPI Auth Example",
        version="1.0.0",
        description="Swagger UI with Bearer Token Authorization",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

