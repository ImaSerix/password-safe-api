# Password Safe API

Password Safe API is a learning/portfolio project focused on building a secure backend for storing user secrets in an encrypted form.

The main goal of the project is to store and return arbitrary JSON data without the server ever knowing its structure or contents in plaintext.

## What problem does it solve?

The API allows users to securely store any JSON-valid data in encrypted form.

Only the user who knows the password used during encryption can access the stored secrets.  
Even if the database is compromised, the attacker cannot read the stored data.

## Core ideas
- User password acts as a master secret for deriving the encryption key
- The server never knows the structure or meaning of stored data
- Encrypted data is treated as an opaque blob
- Sensitive information (passwords, encryption keys) exists only within a single request lifecycle

## Architecture overview
Request flow:
HTTP request -> middleware -> handler -> service -> repository

### Layers:
**Middleware**
- Authenticates user using credentials from headers
- Derives encryption key
- Injects user and crypto key into request context

**Handler**
- Parses request payload
- Validates input
- Passes raw data to service layer

**Service**
- Implements business logic
- Encrypts/decrypts secrets
- Uses repository for persistence

**Repository**
- Handles database access

This separation keeps responsibilities isolated and allows individual layers to be replaced or improved independently.

## API

### Public routes

#### POST /register
Creates a new user.

Request:
```json
{
  "username": "...",
  "password": "..."
}
```
Constraints:
- username: non-empty, max 32 characters
- password: 8–256 characters

Response:

Code | body | description 
--- | --- | --- 
201 | `{"id": UUID, "createdAt": Timestamp}` | User created
400 | error text | Invalid input
409 | "username taken" | Username already exists
500 | "internal error" | Server error

---

### Protected routes

Require headers:
```
X-Username
X-Password
```

#### POST /secrets
Stores a new secret.

Request:
```json
{
  "data": <any valid json>,
}
```

Response:

Code | body | description 
--- | --- | --- 
201 | `{"id": UUID, "createdAt": Timestamp}` | Secret created
400 | error text | Invalid JSON
500 | "internal error" | Encryption/context error

#### GET /secrets
Returns all user secrets.

Response:

Response:

Code | body | description 
--- | --- | --- 
200 | ```[{"id": UUID, "data": <original JSON>, "createdAt": Timestamp}]``` | Secrets returned
404 | "not found" | User don't have secrets
500 | "internal error" | Encryption/context error


## Security assumptions
This project assumes a trusted client environment.

Passwords and data are sent in plaintext over the network (TLS is expected in real deployment).

The focus of the project is encrypted-at-rest storage.

## What is intentionally missing
- Session-based authentication (credentials are sent on each request by design)
- Updating and deleting secrets (may be added later)

These decisions were made to keep the server as stateless and data-agnostic as possible.

## Running locally

1. Prepare a PostgreSQL database and user
2. Set connection variables in .env or environment
3. Run migrations from:
```bash
/migrations/postgres
```
(using github.com/golang-migrate/migrate)

4. Start server:
```bash
go run cmd/server/main.go
```
Server will be available at:
```bash
localhost:8080
```

