from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from . import models
from .database import get_db

# Security configuration
SECRET_KEY = "your-secret-key-here"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def validate_query_permissions(user: models.User, query: str, db: Session):
    """Validate if user has permission to execute the query"""
    # Get department permissions
    permissions = db.query(models.Permission).filter(
        models.Permission.department == user.department
    ).first()
    
    if not permissions:
        return False, "No permissions found for department"
    
    # Extract query type
    query_upper = query.upper()
    query_type = None
    for op in ["SELECT", "INSERT", "UPDATE", "DELETE"]:
        if query_upper.startswith(op):
            query_type = op
            break
    
    if not query_type:
        return False, "Invalid query type"
    
    # Check if operation is allowed
    if query_type not in permissions.allowed_operations:
        return False, f"{query_type} operations not allowed for this department"
    
    # Extract table name (simplified version)
    table_name = None
    if "FROM" in query_upper:
        parts = query_upper.split("FROM")[1].strip().split()
        if parts:
            table_name = parts[0]
    
    if not table_name or table_name not in permissions.allowed_tables:
        return False, "Access to this table is not allowed"
    
    return True, "Query authorized" 