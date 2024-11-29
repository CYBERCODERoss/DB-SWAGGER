from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import json

from . import models, security
from .database import engine, get_db
from .ml_model import AnomalyDetector
from typing import List, Optional
from pydantic import BaseModel

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Database Intrusion Detection System",
    description="An ML-powered system for detecting and preventing database intrusions",
    version="1.0.0"
)

# Initialize ML model
anomaly_detector = AnomalyDetector()

# Pydantic models for request/response
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    department: str
    is_admin: bool = False

class QueryRequest(BaseModel):
    query: str

class QueryResponse(BaseModel):
    success: bool
    message: str
    is_anomaly: Optional[bool] = None
    features: Optional[dict] = None

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=dict)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        department=user.department,
        is_admin=user.is_admin
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User created successfully"}

@app.post("/permissions/", response_model=dict)
async def create_permission(
    department: str,
    allowed_operations: List[str],
    allowed_tables: List[str],
    current_user: models.User = Depends(security.get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db_permission = models.Permission(
        department=department,
        allowed_operations=allowed_operations,
        allowed_tables=allowed_tables
    )
    db.add(db_permission)
    db.commit()
    return {"message": "Permissions created successfully"}

@app.post("/query/", response_model=QueryResponse)
async def execute_query(
    query_request: QueryRequest,
    current_user: models.User = Depends(security.get_current_user),
    db: Session = Depends(get_db)
):
    # Step 1: Validate permissions
    is_authorized, auth_message = security.validate_query_permissions(
        current_user, query_request.query, db
    )
    if not is_authorized:
        return QueryResponse(success=False, message=auth_message)
    
    # Step 2: Check for anomalies
    is_anomaly, features = anomaly_detector.is_anomaly(query_request.query)
    
    # Log the query
    query_log = models.QueryLog(
        user_id=current_user.id,
        query=query_request.query,
        query_type=query_request.query.split()[0].upper(),
        is_anomaly=is_anomaly,
        features=features
    )
    db.add(query_log)
    db.commit()
    
    # If anomaly detected, block the query
    if is_anomaly:
        return QueryResponse(
            success=False,
            message="Query blocked: Potential security threat detected",
            is_anomaly=True,
            features=features
        )
    
    # In a real system, you would execute the query here
    # For demo purposes, we'll just return success
    return QueryResponse(
        success=True,
        message="Query authorized and executed successfully",
        is_anomaly=False,
        features=features
    )

@app.post("/train/", response_model=dict)
async def train_model(
    current_user: models.User = Depends(security.get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get all non-anomalous queries from logs
    query_logs = db.query(models.QueryLog).filter(
        models.QueryLog.is_anomaly == False
    ).all()
    
    if not query_logs:
        return {"message": "No training data available"}
    
    # Train the model
    queries = [log.query for log in query_logs]
    anomaly_detector.train(queries)
    
    return {"message": "Model trained successfully"} 