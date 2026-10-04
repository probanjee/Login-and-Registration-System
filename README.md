## **Login and Registration System (C++17)**

An advanced, console-based Login and Registration System with **proper authentication and authorization**, developed using modern C++17 practices.

## Security Architecture

### Authentication (Who are you?)
- **PBKDF2-HMAC-SHA256** password hashing with **100,000 iterations** (OWASP recommended)
- **16-byte cryptographic random salt** per user (prevents rainbow table attacks)
- **Constant-time comparison** for hash verification (prevents timing attacks)
- Self-contained SHA-256 → HMAC-SHA-256 → PBKDF2 implementation (no external libraries)
- Brute-force protection with attempt limiting (3 attempts per login)
- Vague error messages to prevent user enumeration

### Authorization (What are you allowed to do?)
- **Role-Based Access Control (RBAC)** with three roles:

| Role        | Permissions                                                      |
|-------------|------------------------------------------------------------------|
| `user`      | View own profile, change own password                            |
| `moderator` | Everything above + view all registered users                     |
| `admin`     | Full access: delete users, assign roles, view system info        |

- Explicit permission checks before every protected action
- Clear denial messages with role and permission details on unauthorized access
- Authentication and authorization are **separate layers** — logging in doesn't grant all access

### Session Model
- A `Session` object is created after successful authentication
- Session tracks: username, role, user ID, login timestamp
- All protected operations validate the session before executing
- Explicit logout terminates the session

## Data Storage Format

Each user is stored in a `<username>.dat` file with structured fields:
```
<salt_hex>:<hash_hex>     ← PBKDF2-HMAC-SHA256 password hash
<role>                     ← admin | moderator | user
<user_id>                  ← unique numeric identifier
<created_at>               ← registration timestamp
```

## Features
- Secure user registration with strong password hashing
- Login with credential verification using PBKDF2
- Session-based identity tracking after login
- Protected actions gated by role permissions
- Password change with old password verification
- Admin: delete users, assign roles, view system info
- Moderator: view all registered users
- Input sanitization and password strength validation
- Menu-driven interactive interface

## How to Compile and Run
```bash
g++ -std=c++17 file.cpp -o auth
./auth
```

> **Note**: First login may take a moment — PBKDF2 with 100,000 iterations is intentionally slow to resist brute-force attacks.

### Creating an Admin Account
New accounts default to the `user` role. To bootstrap the first admin:
1. Register a user normally
2. Manually edit their `.dat` file and change line 2 from `user` to `admin`
3. Login as that admin — you can now assign roles to other users from the menu

## Technologies Used
- Language: C++ (C++17 standard)
- IDE: Visual Studio Code
- Compiler: g++ (MinGW)
- Platform: Console Application
- Crypto: PBKDF2-HMAC-SHA256 (self-contained, no external dependencies)

## Password Policy
- Minimum 8 characters
- Must contain uppercase, lowercase, and digit
- Sanitized for invalid characters

## Internship Details
- Organization: CodeAlpha
- Domain: C++ Programming
