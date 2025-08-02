from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import APIKeyHeader
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
# omkar

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

