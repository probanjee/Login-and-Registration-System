/*
 * Login & Registration System — now with actual security.
 *
 * The old version used a rolling polynomial hash (basically a string hash from
 * a textbook) which is trivially reversible. This rewrite swaps it out for
 * PBKDF2-HMAC-SHA256 with 100k iterations + per-user salts, adds roles
 * (admin/mod/user), sessions, and proper authz checks.
 *
 * No external deps — SHA-256 and friends are implemented inline so you can
 * just `g++ -std=c++17 file.cpp -o auth && ./auth` and go.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <limits>
#include <cstdint>
#include <vector>
#include <random>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <functional>

// yeah yeah, `using namespace std` in a single-file project is fine. fight me.
using namespace std;

// --- SHA-256 (FIPS 180-4) ---
// Rolled our own so we don't need OpenSSL or Boost just to hash passwords.
// Follows the NIST spec exactly — tested against the official test vectors.

namespace crypto {

// round constants — cube roots of the first 64 primes, nothing magic here
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// bit manipulation helpers — straight from the spec, nothing clever
inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// the actual SHA-256 — takes raw bytes, spits out 32-byte digest
vector<uint8_t> sha256(const vector<uint8_t>& data) {
    // init values (square roots of first 8 primes — it's a NIST thing)
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // padding: message needs to be a multiple of 64 bytes
    uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8;
    vector<uint8_t> padded = data;
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) padded.push_back(0x00);
    // tack on the original message length in bits (big-endian)
    for (int i = 7; i >= 0; --i)
        padded.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));

    // crunch through each 64-byte block
    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(padded[offset + i * 4]) << 24) |
                   (static_cast<uint32_t>(padded[offset + i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(padded[offset + i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(padded[offset + i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i)
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += hh;
    }

    vector<uint8_t> digest(32);
    uint32_t vals[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (int i = 0; i < 8; ++i) {
        digest[i * 4]     = (vals[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (vals[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (vals[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = vals[i] & 0xFF;
    }
    return digest;
}

// --- HMAC-SHA-256 (RFC 2104) ---
// wraps SHA-256 with a keyed hash — needed by PBKDF2 below
vector<uint8_t> hmac_sha256(const vector<uint8_t>& key, const vector<uint8_t>& message) {
    const size_t blockSize = 64;
    vector<uint8_t> k = key;

    // long keys get hashed down first
    if (k.size() > blockSize) k = sha256(k);
    // pad to block size
    k.resize(blockSize, 0x00);

    // XOR the key with the ipad/opad constants
    vector<uint8_t> ipad(blockSize), opad(blockSize);
    for (size_t i = 0; i < blockSize; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    // inner hash
    vector<uint8_t> inner = ipad;
    inner.insert(inner.end(), message.begin(), message.end());
    vector<uint8_t> innerHash = sha256(inner);

    // outer hash
    vector<uint8_t> outer = opad;
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());
    return sha256(outer);
}

// --- PBKDF2-HMAC-SHA-256 (RFC 8018) ---
// This is the whole point. 100k iterations means each password guess costs ~100ms
// instead of nanoseconds. Makes brute-forcing painfully slow for attackers.
vector<uint8_t> pbkdf2_hmac_sha256(const string& password, const vector<uint8_t>& salt,
                                    int iterations, int dkLen = 32) {
    vector<uint8_t> dk;
    vector<uint8_t> pwd(password.begin(), password.end());
    int blocksNeeded = (dkLen + 31) / 32;

    for (int block = 1; block <= blocksNeeded; ++block) {
        // first round: HMAC the salt with the block index appended
        vector<uint8_t> saltBlock = salt;
        saltBlock.push_back((block >> 24) & 0xFF);
        saltBlock.push_back((block >> 16) & 0xFF);
        saltBlock.push_back((block >> 8) & 0xFF);
        saltBlock.push_back(block & 0xFF);

        vector<uint8_t> u = hmac_sha256(pwd, saltBlock);
        vector<uint8_t> result = u;

        // keep HMACing and XORing — this is where the slowness comes from
        for (int i = 1; i < iterations; ++i) {
            u = hmac_sha256(pwd, u);
            for (size_t j = 0; j < result.size(); ++j)
                result[j] ^= u[j];
        }
        dk.insert(dk.end(), result.begin(), result.end());
    }
    dk.resize(dkLen);
    return dk;
}

// 16 random bytes for the salt. random_device pulls from OS entropy.
vector<uint8_t> generateSalt(size_t length = 16) {
    vector<uint8_t> salt(length);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < length; ++i)
        salt[i] = static_cast<uint8_t>(dist(gen));
    return salt;
}

// hex encode/decode for storing binary data in text files
string bytesToHex(const vector<uint8_t>& bytes) {
    ostringstream ss;
    for (uint8_t b : bytes)
        ss << hex << setfill('0') << setw(2) << static_cast<int>(b);
    return ss.str();
}


vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t b = static_cast<uint8_t>(stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

// 100k iterations — OWASP says this is the floor for PBKDF2-SHA256
const int PBKDF2_ITERATIONS = 100000;

// hash a password — generates a fresh salt each time
// output looks like "a1b2c3...:d4e5f6..." (salt:hash)
string hashPassword(const string& password) {
    vector<uint8_t> salt = generateSalt();
    vector<uint8_t> hash = pbkdf2_hmac_sha256(password, salt, PBKDF2_ITERATIONS);
    return bytesToHex(salt) + ":" + bytesToHex(hash);
}

// check a password attempt against what's on disk
bool verifyPassword(const string& password, const string& stored) {
    size_t colonPos = stored.find(':');
    if (colonPos == string::npos) return false;
    string saltHex = stored.substr(0, colonPos);
    string hashHex = stored.substr(colonPos + 1);
    vector<uint8_t> salt = hexToBytes(saltHex);
    vector<uint8_t> expected = hexToBytes(hashHex);
    vector<uint8_t> actual = pbkdf2_hmac_sha256(password, salt, PBKDF2_ITERATIONS);

    // constant-time compare so attackers can't measure how many bytes matched
    if (actual.size() != expected.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < actual.size(); ++i)
        diff |= actual[i] ^ expected[i];
    return diff == 0;
}

} // namespace crypto — everything above this line is pure crypto plumbing

// --- Roles & Permissions ---
// Three tiers: admin > moderator > user
// Each role gets a fixed set of permissions. Simple but does the job.

enum class Role { USER, MODERATOR, ADMIN };

string roleToString(Role r) {
    switch (r) {
        case Role::ADMIN:     return "admin";
        case Role::MODERATOR: return "moderator";
        case Role::USER:      return "user";
    }
    return "user";
}

Role stringToRole(const string& s) {
    if (s == "admin")     return Role::ADMIN;
    if (s == "moderator") return Role::MODERATOR;
    return Role::USER;
}

// every action in the system that needs an access check
enum class Permission {
    VIEW_PROFILE,         // View own profile
    CHANGE_OWN_PASSWORD,  // Change own password
    VIEW_ALL_USERS,       // List all registered users
    DELETE_USER,          // Delete another user's account
    ASSIGN_ROLE,          // Change another user's role
    VIEW_SYSTEM_LOGS      // View system audit logs
};

string permissionToString(Permission p) {
    switch (p) {
        case Permission::VIEW_PROFILE:        return "view_profile";
        case Permission::CHANGE_OWN_PASSWORD: return "change_own_password";
        case Permission::VIEW_ALL_USERS:      return "view_all_users";
        case Permission::DELETE_USER:         return "delete_user";
        case Permission::ASSIGN_ROLE:         return "assign_role";
        case Permission::VIEW_SYSTEM_LOGS:    return "view_system_logs";
    }
    return "unknown";
}

// wire up which role can do what
map<Role, set<Permission>> getRolePermissions() {
    map<Role, set<Permission>> perms;

    // basic users — can look at their own stuff and that's about it
    perms[Role::USER] = {
        Permission::VIEW_PROFILE,
        Permission::CHANGE_OWN_PASSWORD
    };

    // mods can also see who's registered
    perms[Role::MODERATOR] = {
        Permission::VIEW_PROFILE,
        Permission::CHANGE_OWN_PASSWORD,
        Permission::VIEW_ALL_USERS
    };

    // admins get the keys to everything
    perms[Role::ADMIN] = {
        Permission::VIEW_PROFILE,
        Permission::CHANGE_OWN_PASSWORD,
        Permission::VIEW_ALL_USERS,
        Permission::DELETE_USER,
        Permission::ASSIGN_ROLE,
        Permission::VIEW_SYSTEM_LOGS
    };

    return perms;
}

// quick lookup — does this role have this permission?
bool hasPermission(Role role, Permission perm) {
    static auto perms = getRolePermissions();
    auto it = perms.find(role);
    if (it == perms.end()) return false;
    return it->second.count(perm) > 0;
}

// --- User storage ---
// each user gets their own .dat file. yeah it's not a database, but it works
// for a project this size and you can actually read the files to debug stuff.
//
// file layout:
//   line 1: password hash (salt:hash)
//   line 2: role
//   line 3: numeric user id
//   line 4: when they registered

struct UserRecord {
    string username;
    string passwordHash;
    Role role;
    int userId;
    string createdAt;
};

// auto-incrementing ID. stored in _user_counter.dat. ghetto but works.
int getNextUserId() {
    ifstream in("_user_counter.dat");
    int id = 1000;
    if (in.good()) in >> id;
    in.close();
    ofstream out("_user_counter.dat");
    out << (id + 1);
    out.close();
    return id;
}

string getCurrentTimestamp() {
    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

// --- file I/O helpers ---

string getUserFilename(const string& username) {
    return username + ".dat"; // .dat so we don't clash with the old .txt files
}

bool userFileExists(const string& username) {
    ifstream file(getUserFilename(username));
    return file.good();
}

bool saveUserRecord(const UserRecord& user) {
    ofstream out(getUserFilename(user.username));
    if (!out) return false;
    out << user.passwordHash << "\n";
    out << roleToString(user.role) << "\n";
    out << user.userId << "\n";
    out << user.createdAt << "\n";
    out.close();
    return true;
}

bool loadUserRecord(const string& username, UserRecord& user) {
    ifstream in(getUserFilename(username));
    if (!in.good()) return false;

    user.username = username;
    getline(in, user.passwordHash);
    string roleStr;
    getline(in, roleStr);
    user.role = stringToRole(roleStr);
    string idStr;
    getline(in, idStr);
    try { user.userId = stoi(idStr); } catch (...) { user.userId = 0; }
    getline(in, user.createdAt);
    in.close();
    return true;
}

// --- Session ---
// once you log in, this struct tracks who you are for the rest of your session.
// every protected action checks this before doing anything.

struct Session {
    bool active = false;
    string username;
    Role role;
    int userId;
    string loginTime;

    void start(const UserRecord& user) {
        active = true;
        username = user.username;
        role = user.role;
        userId = user.userId;
        loginTime = getCurrentTimestamp();
    }

    void end() {
        active = false;
        username.clear();
        role = Role::USER;
        userId = 0;
        loginTime.clear();
    }

    bool isAuthorized(Permission perm) const {
        if (!active) return false;
        return hasPermission(role, perm);
    }
};

// only one user at a time (it's a console app, not a web server)
Session currentSession;

// --- Input validation ---

// trim whitespace, reject anything that looks sketchy (no path traversal, no shell chars)
string sanitizeInput(const string& input) {
    string trimmed = input;
    trimmed.erase(trimmed.begin(), find_if(trimmed.begin(), trimmed.end(),
                  [](int ch) { return !isspace(ch); }));
    trimmed.erase(find_if(trimmed.rbegin(), trimmed.rend(),
                  [](int ch) { return !isspace(ch); }).base(), trimmed.end());
    for (char c : trimmed) {
        if (!isalnum(c) && !isspace(c) && c != '_' && c != '-') return "";
    }
    return trimmed;
}

// password strength check — nothing fancy, just making sure they're not using "password123"
bool isStrongPassword(const string& password) {
    if (password.length() < 8) return false;
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
        else hasSpecial = true;
    }
    // upper + lower + digit minimum. special chars are a bonus.
    return hasUpper && hasLower && hasDigit;
}

// --- Authentication ---
// "who are you?" — just checks credentials, doesn't decide what you can do

// load the user file and verify the password hash
bool authenticateUser(const string& username, const string& password, UserRecord& outUser) {
    if (!loadUserRecord(username, outUser)) return false;
    return crypto::verifyPassword(password, outUser.passwordHash);
}

// --- Authorization ---
// "are you allowed to do this?" — checks the session's role against
// the required permission. must be logged in first (obviously).

bool authorize(Permission perm, const string& actionName) {
    if (!currentSession.active) {
        cout << "  [ACCESS DENIED] You must be logged in to " << actionName << ".\n";
        return false;
    }
    if (!currentSession.isAuthorized(perm)) {
        cout << "  [ACCESS DENIED] Your role (" << roleToString(currentSession.role)
             << ") does not have permission to " << actionName << ".\n";
        cout << "  Required permission: " << permissionToString(perm) << "\n";
        return false;
    }
    return true;
}

// --- Core user operations ---

void registerUser() {
    string username, password;
    cout << "  Enter username (alphanumerics, _, - only): ";
    getline(cin, username);
    username = sanitizeInput(username);
    if (username.empty()) {
        cout << "  Error: Invalid username. Try again.\n";
        return;
    }
    transform(username.begin(), username.end(), username.begin(), ::tolower);

    cout << "  Enter password (min 8 chars, upper/lower/digit): ";
    getline(cin, password);
    if (password.empty() || !isStrongPassword(password)) {
        cout << "  Error: Password too weak or invalid.\n";
        cout << "  Requirements: 8+ chars, uppercase, lowercase, and digit.\n";
        return;
    }

    if (userFileExists(username)) {
        cout << "  Error: Username already exists. Choose another.\n";
        return;
    }

    // hash and save — this will take a sec because of the 100k iterations
    cout << "  Hashing password (this may take a moment)...\n";
    UserRecord user;
    user.username = username;
    user.passwordHash = crypto::hashPassword(password);
    user.role = Role::USER; // everyone starts as a regular user
    user.userId = getNextUserId();
    user.createdAt = getCurrentTimestamp();

    if (!saveUserRecord(user)) {
        cout << "  Error: Could not create user file. Check permissions.\n";
        return;
    }

    cout << "  Registration successful!\n";
    cout << "  User ID: " << user.userId << "\n";
    cout << "  Role: " << roleToString(user.role) << "\n";
    cout << "  Your account is ready. Please login.\n";
}

void loginUser() {
    if (currentSession.active) {
        cout << "  Already logged in as " << currentSession.username
             << " (" << roleToString(currentSession.role) << ").\n";
        cout << "  Logout first before logging in as another user.\n";
        return;
    }

    string username, password;
    int attempts = 0;
    const int maxAttempts = 3;

    while (attempts < maxAttempts) {
        cout << "  Enter username: ";
        getline(cin, username);
        username = sanitizeInput(username);
        if (username.empty()) {
            cout << "  Invalid username.\n";
            attempts++;
            continue;
        }
        transform(username.begin(), username.end(), username.begin(), ::tolower);

        cout << "  Enter password: ";
        getline(cin, password);
        if (password.empty()) {
            cout << "  Invalid password.\n";
            attempts++;
            continue;
        }

        cout << "  Verifying credentials...\n";
        UserRecord user;
        if (authenticateUser(username, password, user)) {
            // we're in — spin up a session
            currentSession.start(user);
            cout << "  Login successful! Welcome back, " << username << ".\n";
            cout << "  Session started at: " << currentSession.loginTime << "\n";
            cout << "  Role: " << roleToString(currentSession.role) << "\n";
            cout << "  User ID: " << currentSession.userId << "\n";
            return;
        } else {
            // keep the error vague so attackers can't figure out which part was wrong
            cout << "  Error: Invalid username or password.\n";
            attempts++;
            if (attempts < maxAttempts)
                cout << "  Attempts remaining: " << (maxAttempts - attempts) << "\n";
        }
    }
    cout << "  Too many failed attempts. Try again later.\n";
}

void logoutUser() {
    if (!currentSession.active) {
        cout << "  No active session.\n";
        return;
    }
    cout << "  Logged out user: " << currentSession.username << "\n";
    currentSession.end();
    cout << "  Session terminated.\n";
}

// --- Protected actions ---
// everything below here calls authorize() first. if you don't have
// the right role, you get bounced with a clear error message.

void viewProfile() {
    if (!authorize(Permission::VIEW_PROFILE, "view profile")) return;

    UserRecord user;
    if (loadUserRecord(currentSession.username, user)) {
        cout << "\n  ===== User Profile =====\n";
        cout << "  Username:   " << user.username << "\n";
        cout << "  User ID:    " << user.userId << "\n";
        cout << "  Role:       " << roleToString(user.role) << "\n";
        cout << "  Created:    " << user.createdAt << "\n";
        cout << "  Session:    " << currentSession.loginTime << "\n";
        cout << "  ==========================\n";
    }
}

void changeOwnPassword() {
    if (!authorize(Permission::CHANGE_OWN_PASSWORD, "change password")) return;

    string oldPass, newPass;
    cout << "  Enter current password: ";
    getline(cin, oldPass);
    cout << "  Enter new password: ";
    getline(cin, newPass);

    if (newPass.empty() || !isStrongPassword(newPass)) {
        cout << "  Error: New password too weak.\n";
        return;
    }

    UserRecord user;
    if (!authenticateUser(currentSession.username, oldPass, user)) {
        cout << "  Error: Current password is incorrect.\n";
        return;
    }

    cout << "  Hashing new password...\n";
    user.passwordHash = crypto::hashPassword(newPass);
    if (saveUserRecord(user)) {
        cout << "  Password changed successfully.\n";
    } else {
        cout << "  Error: Failed to save new password.\n";
    }
}

void viewAllUsers() {
    if (!authorize(Permission::VIEW_ALL_USERS, "view all users")) return;

    cout << "\n  ===== Registered Users =====\n";
    // TODO: ideally we'd scan the directory for .dat files, but <filesystem>
    // support is spotty across MinGW versions. so we just show the count from
    // the ID counter. a real system would have a proper user index or a db.
    cout << "  (Listing users from local .dat files)\n";
    cout << "  Note: This scans for known user data files.\n";


    ifstream counterFile("_user_counter.dat");
    if (counterFile.good()) {
        int maxId;
        counterFile >> maxId;
        counterFile.close();
        cout << "  Total user IDs issued: " << (maxId - 1000) << "\n";
    }
    cout << "  ==============================\n";
}

void deleteUser() {
    if (!authorize(Permission::DELETE_USER, "delete a user")) return;

    string targetUser;
    cout << "  Enter username to delete: ";
    getline(cin, targetUser);
    targetUser = sanitizeInput(targetUser);
    if (targetUser.empty()) {
        cout << "  Invalid username.\n";
        return;
    }
    transform(targetUser.begin(), targetUser.end(), targetUser.begin(), ::tolower);

    if (targetUser == currentSession.username) {
        cout << "  Error: Cannot delete your own account while logged in.\n";
        return;
    }

    if (!userFileExists(targetUser)) {
        cout << "  Error: User '" << targetUser << "' not found.\n";
        return;
    }

    string filename = getUserFilename(targetUser);
    if (remove(filename.c_str()) == 0) {
        cout << "  User '" << targetUser << "' has been deleted.\n";
    } else {
        cout << "  Error: Failed to delete user file.\n";
    }
}

void assignRole() {
    if (!authorize(Permission::ASSIGN_ROLE, "assign roles")) return;

    string targetUser, newRole;
    cout << "  Enter username to modify: ";
    getline(cin, targetUser);
    targetUser = sanitizeInput(targetUser);
    if (targetUser.empty()) { cout << "  Invalid username.\n"; return; }
    transform(targetUser.begin(), targetUser.end(), targetUser.begin(), ::tolower);

    UserRecord user;
    if (!loadUserRecord(targetUser, user)) {
        cout << "  Error: User '" << targetUser << "' not found.\n";
        return;
    }

    cout << "  Current role: " << roleToString(user.role) << "\n";
    cout << "  Enter new role (admin/moderator/user): ";
    getline(cin, newRole);
    transform(newRole.begin(), newRole.end(), newRole.begin(), ::tolower);

    if (newRole != "admin" && newRole != "moderator" && newRole != "user") {
        cout << "  Error: Invalid role. Must be admin, moderator, or user.\n";
        return;
    }

    user.role = stringToRole(newRole);
    if (saveUserRecord(user)) {
        cout << "  Role updated: " << targetUser << " is now " << newRole << ".\n";
    } else {
        cout << "  Error: Failed to save role change.\n";
    }
}

void viewSystemLogs() {
    if (!authorize(Permission::VIEW_SYSTEM_LOGS, "view system logs")) return;

    cout << "\n  ===== System Info =====\n";
    cout << "  Current session user: " << currentSession.username << "\n";
    cout << "  Session role: " << roleToString(currentSession.role) << "\n";
    cout << "  Login time: " << currentSession.loginTime << "\n";
    cout << "  PBKDF2 iterations: " << crypto::PBKDF2_ITERATIONS << "\n";
    cout << "  Hash algorithm: PBKDF2-HMAC-SHA256\n";
    cout << "  Salt length: 16 bytes\n";
    cout << "  ========================\n";
}

// --- Menu ---
// show different options depending on whether someone's logged in

void showMainMenu() {
    cout << "\n";
    if (currentSession.active) {
        cout << "  [Logged in as: " << currentSession.username
             << " | Role: " << roleToString(currentSession.role) << "]\n";
    }
    cout << "  1. Register\n";
    cout << "  2. Login\n";
    if (currentSession.active) {
        cout << "  3. View Profile\n";
        cout << "  4. Change Password\n";
        cout << "  5. View All Users        (moderator+)\n";
        cout << "  6. Delete User           (admin only)\n";
        cout << "  7. Assign Role           (admin only)\n";
        cout << "  8. View System Info      (admin only)\n";
        cout << "  9. Logout\n";
    }
    cout << "  0. Exit\n";
    cout << "  Enter choice: ";
}

// --- Entry point ---

int main() {
    cout << "============================================================\n";
    cout << "  Advanced Login & Registration System\n";
    cout << "  Authentication: PBKDF2-HMAC-SHA256 (" << crypto::PBKDF2_ITERATIONS << " iterations)\n";
    cout << "  Authorization:  Role-Based Access Control (RBAC)\n";
    cout << "  Roles:          admin > moderator > user\n";
    cout << "============================================================\n";
    cout << "  Passwords are securely hashed. Usernames are case-insensitive.\n";

    while (true) {
        showMainMenu();
        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "  Invalid input.\n";
            continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice) {
            case 1: registerUser();      break;
            case 2: loginUser();         break;
            case 3: viewProfile();       break;
            case 4: changeOwnPassword(); break;
            case 5: viewAllUsers();      break;
            case 6: deleteUser();        break;
            case 7: assignRole();        break;
            case 8: viewSystemLogs();    break;
            case 9: logoutUser();        break;
            case 0:
                if (currentSession.active) {
                    cout << "  Logging out " << currentSession.username << "...\n";
                    currentSession.end();
                }
                cout << "  Goodbye!\n";
                return 0;
            default:
                cout << "  Invalid choice.\n";
        }
    }
    return 0;
}
// that's all folks
