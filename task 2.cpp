// Advanced Login and Registration System in C++
// This program allows users to register and login with hashed passwords stored in individual files.

#include <iostream>  // For input/output operations like cout and cin
#include <fstream>   // For file input/output operations (ifstream for reading files, ofstream for writing files) - used here to store and retrieve user credentials securely in individual files
#include <string>    // For string handling and manipulation
#include <sstream>   // For string stream operations (like converting data to/from strings) - used here to build hex strings from hashed passwords
#include <algorithm> // For algorithms like transform (to convert usernames to lowercase)
#include <cctype>    // For character classification functions like isupper, islower, etc. (used in password strength checks)
#include <limits>    // For numeric_limits (to clear input buffer after cin)

// Using namespace std to keep things readable, but in bigger projects, I'd avoid this to prevent conflicts
using namespace std;

// Simple polynomial rolling hash function - why? To hash passwords securely without external libraries; it's fast and one-way for basic use (not as strong as SHA-256, but fine for this project)
string simpleHash(const string& input) {
    const unsigned long long prime = 31;  // A common prime for hashing
    unsigned long long hash = 0;
    unsigned long long power = 1;
    for (char c : input) {
        hash = (hash + (c - 'a' + 1) * power) % 1000000007;  // Modulo to keep it manageable
        power = (power * prime) % 1000000007;
    }
    stringstream ss;
    ss << hex << hash;  // Convert to hex for storage
    return ss.str();
}

// Simple class to represent a User - this makes the code more organized and extensible
class User {
public:
    string username;
    string hashedPassword;  // We'll store the hashed version, not plain text

    // Constructor to initialize a user
    User(string u, string p) : username(u), hashedPassword(p) {}
};

// Function to hash a password using our simple hash - why? Plain text passwords are a security risk; hashing makes it one-way
string hashPassword(const string& password) {
    return simpleHash(password);  // Use the simple hash function
}

// Function to check password strength - why? Weak passwords are easy to crack, so we enforce basics
bool isStrongPassword(const string& password) {
    if (password.length() < 8) return false;  // At least 8 chars
    bool hasUpper = false, hasLower = false, hasDigit = false;
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
    }
    return hasUpper && hasLower && hasDigit;  // Must have mix of cases and numbers
}

// Function to sanitize input - removes leading/trailing spaces and checks for invalid chars
string sanitizeInput(const string& input) {
    string trimmed = input;
    trimmed.erase(trimmed.begin(), find_if(trimmed.begin(), trimmed.end(), [](int ch) { return !isspace(ch); }));
    trimmed.erase(find_if(trimmed.rbegin(), trimmed.rend(), [](int ch) { return !isspace(ch); }).base(), trimmed.end());
    // Allow alphanumerics, spaces, and basic punctuation - reject anything that could break file parsing
    for (char c : trimmed) {
        if (!isalnum(c) && !isspace(c) && c != '_' && c != '-') return "";  // Invalid char, return empty
    }
    return trimmed;
}

// Function to check if a username file exists - why? For duplicate check and to see if user is registered
bool userFileExists(const string& username) {
    string filename = username + ".txt";  // One file per user for better isolation
    ifstream file(filename);
    return file.good();  // Returns true if file opens successfully
}

// Function to register a new user
void registerUser() {
    string username, password;
    cout << "Enter username (alphanumerics, spaces, _, - only): ";
    getline(cin, username);  // Use getline to handle spaces
    username = sanitizeInput(username);
    if (username.empty()) {
        cout << "Error: Invalid username. Try again.\n";
        return;
    }
    // Make username lowercase for case-insensitivity
    transform(username.begin(), username.end(), username.begin(), ::tolower);

    cout << "Enter password (at least 8 chars, mix of upper/lower/digits): ";
    getline(cin, password);
    password = sanitizeInput(password);
    if (password.empty() || !isStrongPassword(password)) {
        cout << "Error: Password too weak or invalid. Try again.\n";
        return;
    }

    // Check for duplicate
    if (userFileExists(username)) {
        cout << "Error: Username already exists. Choose another.\n";
        return;
    }

    // Hash the password and store in user's file
    string hashed = hashPassword(password);
    string filename = username + ".txt";
    ofstream outfile(filename);
    if (!outfile) {
        cout << "Error: Could not create user file. Check permissions.\n";
        return;
    }
    outfile << hashed << endl;  // Store only the hash
    outfile.close();

    cout << "Registration successful! Your account is ready.\n";
}

// Function to login a user
void loginUser() {
    string username, password;
    int attempts = 0;
    const int maxAttempts = 3;  // Limit attempts to prevent brute force

    while (attempts < maxAttempts) {
        cout << "Enter username: ";
        getline(cin, username);
        username = sanitizeInput(username);
        if (username.empty()) {
            cout << "Invalid username.\n";
            attempts++;
            continue;
        }
        transform(username.begin(), username.end(), username.begin(), ::tolower);

        cout << "Enter password: ";
        getline(cin, password);
        password = sanitizeInput(password);
        if (password.empty()) {
            cout << "Invalid password.\n";
            attempts++;
            continue;
        }

        // Check if user exists and password matches
        string filename = username + ".txt";
        ifstream infile(filename);
        if (!infile) {
            cout << "Error: Username not found.\n";
            attempts++;
            continue;
        }
        string storedHash;
        getline(infile, storedHash);
        infile.close();

        if (hashPassword(password) == storedHash) {
            cout << "Login successful! Welcome back, " << username << ".\n";
            return;  // Success, exit function
        } else {
            cout << "Error: Invalid password.\n";
            attempts++;
        }
    }
    cout << "Too many failed attempts. Try again later.\n";
}

// Main function with a loop for continuous use
int main() {
    cout << "===== Advanced Login and Registration System =====\n";
    cout << "Note: Passwords are hashed for security. Usernames are case-insensitive.\n";

    while (true) {
        cout << "\n1. Register\n2. Login\n3. Exit\nEnter choice: ";
        int choice;
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Clear buffer after cin

        switch (choice) {
            case 1:
                registerUser();
                break;
            case 2:
                loginUser();
                break;
            case 3:
                cout << "Goodbye!\n";
                return 0;
            default:
                cout << "Invalid choice. Pick 1-3.\n";
        }
    }
    return 0;
}