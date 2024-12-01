#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <stdexcept>
#include <cassert>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Add near the top with other global variables
std::string key = "0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256

// Function prototype for decrypt
std::string decrypt(const std::string &cipherText, const std::string &key);

// Function prototype for encrypt
std::string encrypt(const std::string &plainText, const std::string &key);

// Function to get token expiration time
std::time_t getTokenExpiration(const std::string& token) {
    return std::time(nullptr) + 86400; // Token expires in 24 hours
}

// Function to hash the input token using HMAC with SHA-256
std::string hashInputToken(const std::string &inputToken) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_sha256(), inputToken.c_str(), inputToken.length(),
         reinterpret_cast<const unsigned char*>(inputToken.c_str()), inputToken.length(),
         result, &result_len);

    return std::string(result, result + result_len);
}

// Secure comparison function to prevent timing attacks
bool secureCompare(const std::string &a, const std::string &b) {
    if (a.length() != b.length()) {
        return false;
    }

    const char *ap = a.c_str();
    const char *bp = b.c_str();
    char result = 0;
    for (size_t i = 0; i < a.length(); i++) {
        result |= ap[i] ^ bp[i];
    }

    return result == 0;
}

// Structure to represent a log entry
struct LogEntry {
    std::time_t timestamp;
    std::string action; // "enter" or "leave"
    std::string person; // Employee or guest name

    std::string getFormattedTimestamp() const {
        std::tm localTime;
        localtime_s(&localTime, &timestamp);
        std::ostringstream oss;
        oss << std::put_time(&localTime, "%Y-%m-%d_%H:%M:%S");
        return oss.str();
    }

    std::string toString() const {
        return getFormattedTimestamp() + " " + action + " " + person;
    }
};

// Function to get environment variable
std::string getEnvVar(const std::string &key) {
    const char *val = std::getenv(key.c_str());
    return val == nullptr ? std::string() : std::string(val);
}

// Function to check if the token is expired
bool isTokenExpired(const std::string& token) {
    std::time_t expirationTime = getTokenExpiration(token);
    std::time_t currentTime = std::time(nullptr);
    return currentTime > expirationTime;
}

// Function to authenticate the token
bool authenticate(const std::string &token) {
    if (isTokenExpired(token)) {
        std::cerr << "Token expired" << std::endl;
        return false;
    }

    std::string secureToken = getEnvVar("SECURE_TOKEN");

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_sha256(), secureToken.c_str(), secureToken.length(),
         reinterpret_cast<const unsigned char*>(token.c_str()), token.length(),
         result, &result_len);

    std::string hashedToken(result, result + result_len);
    return secureCompare(hashedToken, hashInputToken(token));
}

// Function to validate names (employees or guests)
bool isValidName(const std::string &name) {
    return !name.empty() && std::all_of(name.begin(), name.end(), ::isalpha) && name.length() <= 50;
}

// Function to validate log file names to prevent directory traversal
bool isValidLogFile(const std::string &logFile) {
    if (logFile.empty() || logFile.find("..") != std::string::npos || logFile.find('/') != std::string::npos) {
        std::cerr << "Invalid log file name" << std::endl;
        return false;
    }
    return true;
}

// Function to append a log entry to the log file
bool appendLog(const std::string &logFile, const LogEntry &entry, const std::string &key) {
    std::ofstream file(logFile, std::ios::app);
    if (!file) {
        std::cerr << "Error: Failed to access the log file." << std::endl;
        return false;
    }

    std::string logEntry = entry.toString();
    std::string encryptedEntry = encrypt(logEntry, key);
    std::cout << "Encrypted Entry: " << encryptedEntry << std::endl;

    std::string decryptedEntry = decrypt(encryptedEntry, key);
    std::cout << "Decrypted Entry: " << decryptedEntry << std::endl;

    file << encryptedEntry << std::endl;
    return true;
}

// Function to encrypt data
std::string encrypt(const std::string &plainText, const std::string &key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string cipherText(plainText.size() + AES_BLOCK_SIZE, '\0'); // Ensure enough space
    std::string iv(AES_BLOCK_SIZE, '\0'); // IV buffer
    int len;

    // Generate a random IV
    if (!RAND_bytes((unsigned char*)iv.data(), AES_BLOCK_SIZE)) {
        std::cerr << "Error generating IV" << std::endl;
        return "";
    }

    // Initialize encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str());

    // Encrypt the plaintext
    EVP_EncryptUpdate(ctx, (unsigned char*)&cipherText[0], &len, (unsigned char*)plainText.c_str(), plainText.size());
    int cipherTextLen = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, (unsigned char*)&cipherText[0] + len, &len);
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV to the ciphertext
    return iv + cipherText.substr(0, cipherTextLen);
}

// Add this function definition
std::string decrypt(const std::string &cipherText, const std::string &key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string plainText(cipherText.size(), '\0');
    int len;

    // Extract IV from ciphertext
    std::string iv = cipherText.substr(0, AES_BLOCK_SIZE);
    std::string actualCipherText = cipherText.substr(AES_BLOCK_SIZE);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str());
    EVP_DecryptUpdate(ctx, (unsigned char*)&plainText[0], &len, (unsigned char*)actualCipherText.c_str(), actualCipherText.size());
    int plainTextLen = len;

    EVP_DecryptFinal_ex(ctx, (unsigned char*)&plainText[0] + len, &len);
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return plainText.substr(0, plainTextLen);
}

// Main function to handle command line arguments and log appending
int main(int argc, char *argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: logappend -K <token> (-E <employee-name> | -G <guest-name>) (-A | -L) <log>" << std::endl;
        return 1;
    }

    std::string logFile;
    std::string token;
    std::time_t timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string personName;
    std::string action;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        try {
            if (arg == "-K") {
                if (i + 1 >= argc) throw std::runtime_error("Missing token value");
                token = argv[++i];
            } else if (arg == "-E") {
                if (i + 1 >= argc) throw std::runtime_error("Missing employee name");
                personName = argv[++i];
                if (!isValidName(personName)) {
                    std::cerr << "Invalid name" << std::endl;
                    return 1;
                }
            } else if (arg == "-G") {
                if (i + 1 >= argc) throw std::runtime_error("Missing guest name");
                personName = "Guest_" + std::string(argv[++i]); // Prefix guest names
                if (!isValidName(personName.substr(6))) { // Validate without prefix
                    std::cerr << "Invalid guest name" << std::endl;
                    return 1;
                }
            } else if (arg == "-A") {
                action = "enter";
            } else if (arg == "-L") {
                action = "leave";
            } else {
                logFile = arg;
            }
        } catch (const std::exception &e) {
            std::cerr << "Invalid argument format: " << e.what() << std::endl;
            return 1;
        }
    }

    assert(!token.empty() && "Token should not be empty");
    assert(!personName.empty() && "Person name should not be empty");
    assert(!logFile.empty() && "Log file should not be empty");

    if (!isValidLogFile(logFile)) {
        return 1;
    }

    if (!authenticate(token)) {
        std::cerr << "Authentication failed" << std::endl;
        return 2;
    }

    if (action != "enter" && action != "leave") {
        std::cerr << "Invalid action. Use -A for enter or -L for leave." << std::endl;
        return 1;
    }

    LogEntry newEntry = {timestamp, action, personName};

    if (!appendLog(logFile, newEntry, "0123456789abcdef0123456789abcdef")) {
        std::cerr << "Failed to append log entry" << std::endl;
        return 1;
    }

    std::cout << "Log entry added." << std::endl;
    return 0;
}