# Database Intrusion Detection System

An ML-powered system for detecting and preventing database intrusions using identity-based access control and machine learning.

## Step-by-Step Setup and Usage Guide

### 1. Installation

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --reload
```

### 2. Access Swagger UI
Open your browser and navigate to: http://localhost:8000/docs

### 3. Create Admin User
First, create an admin user using the `POST /users/` endpoint:
```json
{
    "username": "admin",
    "email": "admin@example.com",
    "password": "admin123",
    "department": "IT",
    "is_admin": true
}
```

### 4. Get Admin Token
Use the `POST /token` endpoint to get an access token:
- Username: admin
- Password: admin123

Save the received token for subsequent requests.

### 5. Set Up Department Permissions
Use the `POST /permissions/` endpoint with admin token:
```json
{
    "department": "IT",
    "allowed_operations": ["SELECT", "INSERT", "UPDATE", "DELETE"],
    "allowed_tables": ["accounts", "users", "transactions"]
}
```

Additional department example:
```json
{
    "department": "finance",
    "allowed_operations": ["SELECT", "INSERT"],
    "allowed_tables": ["transactions", "accounts"]
}
```

### 6. Create Regular Users
Create regular users for different departments:
```json
{
    "username": "john_finance",
    "email": "john@finance.com",
    "password": "john123",
    "department": "finance",
    "is_admin": false
}
```

### 7. Execute Queries
Use the `POST /query/` endpoint to execute queries. Here are examples for different operations:

#### SELECT Queries:
```json
{
    "query": "SELECT * FROM accounts WHERE balance > 1000"
}
```

```json
{
    "query": "SELECT * FROM transactions WHERE amount > 500"
}
```

#### INSERT Queries:
```json
{
    "query": "INSERT INTO accounts (customer_id, account_number, balance, account_type) VALUES (1001, 'ACC123456', 5000.00, 'savings')"
}
```

```json
{
    "query": "INSERT INTO transactions (account_id, amount, transaction_type) VALUES (1001, 1500.00, 'deposit')"
}
```

#### UPDATE Queries:
```json
{
    "query": "UPDATE accounts SET balance = balance + 1000 WHERE account_id = 1001"
}
```

### 8. Train the Model
After executing several legitimate queries, use the `POST /train/` endpoint to train the anomaly detection model.

### Example Scenarios

1. **Valid Query (Should Succeed)**:
```json
{
    "query": "SELECT * FROM accounts WHERE customer_id = 123"
}
```

2. **Anomalous Query (Should be Blocked)**:
```json
{
    "query": "SELECT * FROM accounts; DROP TABLE accounts;"
}
```

3. **Unauthorized Table Access (Should be Blocked)**:
```json
{
    "query": "SELECT * FROM admin_logs"
}
```

## Security Features in Action

1. **Permission Validation**:
- Queries are checked against department permissions
- Only allowed operations on allowed tables are permitted

2. **Anomaly Detection**:
- ML model learns from normal query patterns
- Flags suspicious queries that deviate from normal patterns

3. **Query Logging**:
- All queries are logged for audit purposes
- Logs are used to train the ML model

## Common Issues and Solutions

1. "No permissions found for department"
   - Ensure department permissions are set up using POST /permissions/

2. "Access to this table is not allowed"
   - Check if the table is in the department's allowed_tables list

3. "No training data available"
   - Execute more legitimate queries before training the model

## Security Best Practices

1. Change the default SECRET_KEY in production
2. Use strong passwords for admin accounts
3. Regularly review and update department permissions
4. Periodically retrain the ML model with new data
5. Monitor query logs for suspicious patterns

## API Endpoints Summary

- `POST /token`: Get access token
- `POST /users/`: Create new user
- `POST /permissions/`: Set department permissions
- `POST /query/`: Execute SQL queries
- `POST /train/`: Train anomaly detection model