#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdlib>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <algorithm>

std::time_t getTokenExpiration(const std::string& token) {
    return std::time(nullptr) + 86400; // Token expires in 24 hours
}

std::string hashInputToken(const std::string &inputToken) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_sha256(), inputToken.c_str(), inputToken.length(),
         reinterpret_cast<const unsigned char*>(inputToken.c_str()), inputToken.length(),
         result, &result_len);

    return std::string(result, result + result_len);
}

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

struct LogEntry {
    std::time_t timestamp;
    std::string action; // "enter" or "leave"
    std::string person; // Employee or guest name

    LogEntry(std::time_t t, const std::string &a, const std::string &p)
        : timestamp(t), action(a), person(p) {}
};

std::string getEnvVar(const std::string &key) {
    const char *val = std::getenv(key.c_str());
    return val == nullptr ? std::string() : std::string(val);
}

bool isTokenExpired(const std::string& token) {
    return std::time(nullptr) >= getTokenExpiration(token);
}

bool authenticate(const std::string &token) {
    if (isTokenExpired(token)) {
        std::cerr << "Token expired" << std::endl;
        return false;
    }

    std::string secureToken = getEnvVar("SECURE_TOKEN");
    if (secureToken.empty()) {
        std::cerr << "SECURE_TOKEN environment variable not set" << std::endl;
        return false;
    }

    // Calculate HMAC of the input token
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_sha256(), secureToken.c_str(), secureToken.length(),
         reinterpret_cast<const unsigned char*>(token.c_str()), token.length(),
         result, &result_len);

    std::string hashedToken(result, result + result_len);
    
    // Use constant-time comparison
    return secureCompare(hashedToken, hashInputToken(token));
}

bool isValidFilename(const std::string &filename) {
    if (filename.empty()) {
        return false;
    }

    #ifdef _WIN32
    if (filename.find(':') != std::string::npos || 
        filename.find('\\') != std::string::npos) {
        return false;
    }
    #else
    if (filename[0] == '/') {
        return false;
    }
    #endif

    if (filename.find("..") != std::string::npos ||
        filename.find("./") != std::string::npos ||
        filename.find("/.") != std::string::npos) {
        return false;
    }

    if (filename.length() < 4 || 
        filename.substr(filename.length() - 4) != ".txt") {
        return false;
    }

    const std::string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    if (filename.find_first_not_of(validChars) != std::string::npos) {
        return false;
    }

    return true;
}

// Function to decrypt data - must match the one in logappend.cpp exactly
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

// Function to read and decrypt log entries from the log file
bool readLog(std::vector<LogEntry> &entries, const std::string &logFile, const std::string &key) {
    if (!isValidFilename(logFile)) {
        std::cerr << "Invalid file path" << std::endl;
        return false;
    }

    std::ifstream file(logFile, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open log file" << std::endl;
        return false;
    }

    std::string encryptedEntry;
    while (std::getline(file, encryptedEntry)) {
        if (encryptedEntry.empty()) {
            continue; // Skip empty entries
        }

        std::string decryptedEntry = decrypt(encryptedEntry, key);
        
        if (decryptedEntry.empty()) {
            std::cerr << "Decryption failed for entry: " << encryptedEntry << std::endl;
            continue; // Skip failed decryption
        }

        // Trim any unwanted characters from the decrypted entry
        decryptedEntry.erase(std::remove_if(decryptedEntry.begin(), decryptedEntry.end(), [](unsigned char c) {
            return !std::isprint(c); // Keep only printable characters
        }), decryptedEntry.end());

        std::istringstream ss(decryptedEntry);
        std::string timestampStr, action, person;

        ss >> timestampStr >> action >> person;
        std::tm tm = {};
        std::istringstream ts(timestampStr);
        ts >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S");
        if (ts.fail()) {
            std::cerr << "Failed to parse timestamp: " << timestampStr << std::endl;
            continue;
        }
        std::time_t timestamp = std::mktime(&tm);
        if (action != "enter" && action != "leave") {
            std::cerr << "Invalid action in log entry: " << action << std::endl;
            continue;
        }
        entries.emplace_back(timestamp, action, person);
    }
    return true;
}

// Function to print the current state of employees and guests
void printCurrentState(const std::vector<LogEntry> &entries) {
    std::set<std::string> employeesInGallery;
    std::set<std::string> guestsInGallery;

    for (const auto &entry : entries) {
        if (entry.action == "enter") {
            if (entry.person.find("Guest_") == 0) {
                guestsInGallery.insert(entry.person.substr(6)); // Remove "Guest_" prefix
            } else {
                employeesInGallery.insert(entry.person);
            }
        } else if (entry.action == "leave") {
            if (entry.person.find("Guest_") == 0) {
                guestsInGallery.erase(entry.person.substr(6));
            } else {
                employeesInGallery.erase(entry.person);
            }
        }
    }

    std::cout << "Employees in gallery: ";
    if (employeesInGallery.empty()) {
        std::cout << "none\n";
    } else {
        for (auto it = employeesInGallery.begin(); it != employeesInGallery.end(); ++it) {
            std::cout << *it;
            if (std::next(it) != employeesInGallery.end()) std::cout << ", ";
        }
        std::cout << "\n";
    }

    std::cout << "Guests in gallery: ";
    if (guestsInGallery.empty()) {
        std::cout << "none\n";
    } else {
        for (auto it = guestsInGallery.begin(); it != guestsInGallery.end(); ++it) {
            std::cout << *it;
            if (std::next(it) != guestsInGallery.end()) std::cout << ", ";
        }
        std::cout << "\n";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4 || std::string(argv[1]) != "-K") {
        std::cerr << "Usage: logread -K <token> <log>" << std::endl;
        return 1;
    }

    std::string token = argv[2];
    std::string logFile = argv[3];
    std::string key = "0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256

    if (!authenticate(token)) {
        std::cerr << "Authentication failed: invalid token" << std::endl;
        return 2;
    }

    std::vector<LogEntry> entries;
    if (!readLog(entries, logFile, key)) {
        std::cerr << "Failed to read log file: " << logFile << std::endl;
        return 1;
    }

    printCurrentState(entries);
    return 0;
}