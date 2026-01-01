# CodeAlpha_Login-and-Registration-System
An advanced Login and Registration System built using C++17 with file-based user authentication, password hashing, input sanitization, and basic security controls. Developed using Visual Studio Code during the CodeAlpha Internship.
# Login and Registration System (C++17)

An advanced, console-based Login and Registration System developed using modern C++17 practices.  
The system provides secure user authentication through password hashing, input validation, and file-based credential storage.

## Key Features
- User registration with secure password hashing
- Login authentication with limited attempts
- Case-insensitive username handling
- Password strength validation
- Input sanitization to prevent invalid data
- File-based credential storage (one file per user)
- Menu-driven interactive interface

## Technical Highlights
- Password hashing (polynomial rolling hash)
- File I/O with proper validation
- Input sanitization and normalization
- Brute-force protection using attempt limits
- STL algorithms and utilities
- Modular and extensible design

## Technologies Used
- Language: C++ (C++17 standard)
- IDE: Visual Studio Code
- Compiler: g++ (MinGW)
- Platform: Console Application

## How to Compile and Run
```bash
g++ -std=c++17 main.cpp -o auth
./auth

## Internship Details
- Organization: CodeAlpha
- Domain: C++ Programming
