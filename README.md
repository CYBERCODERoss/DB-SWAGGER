# Database Intrusion Detection System

An ML-powered system for detecting and preventing database intrusions, implementing identity-based access control and anomaly detection using unsupervised machine learning.

## Features

- Identity-based access control with department-specific permissions
- Machine learning-based anomaly detection for SQL queries
- Real-time query validation and logging
- Role-based access control (Admin/User)
- Swagger UI documentation
- Token-based authentication

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd database-ids
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the server:
```bash
uvicorn app.main:app --reload
```

2. Access the Swagger documentation at: http://localhost:8000/docs

## API Endpoints

### Authentication
- `POST /token`: Get access token (login)

### User Management
- `POST /users/`: Create new user

### Permissions
- `POST /permissions/`: Create department permissions (Admin only)

### Query Management
- `POST /query/`: Execute and validate SQL query
- `POST /train/`: Train anomaly detection model (Admin only)

## Example Usage

1. Create a user:
```bash
curl -X POST "http://localhost:8000/users/" -H "Content-Type: application/json" -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secret123",
    "department": "finance",
    "is_admin": false
}'
```

2. Get access token:
```bash
curl -X POST "http://localhost:8000/token" -d "username=john_doe&password=secret123"
```

3. Create department permissions (as admin):
```bash
curl -X POST "http://localhost:8000/permissions/" \
    -H "Authorization: Bearer <your-token>" \
    -H "Content-Type: application/json" \
    -d '{
        "department": "finance",
        "allowed_operations": ["SELECT", "INSERT"],
        "allowed_tables": ["transactions", "accounts"]
    }'
```

4. Execute a query:
```bash
curl -X POST "http://localhost:8000/query/" \
    -H "Authorization: Bearer <your-token>" \
    -H "Content-Type: application/json" \
    -d '{
        "query": "SELECT * FROM transactions WHERE amount > 1000"
    }'
```

## Security Features

1. **Identity-Based Access Control**
   - Department-specific permissions
   - Role-based access (Admin/User)
   - Token-based authentication

2. **Machine Learning Anomaly Detection**
   - Unsupervised learning (Isolation Forest & DBSCAN)
   - Feature extraction from SQL queries
   - Continuous model training

3. **Query Validation**
   - Permission-based validation
   - Anomaly detection
   - Query logging

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request 