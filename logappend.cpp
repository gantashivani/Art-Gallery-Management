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
        return getFormattedTimestamp() + " " + action + " " + person; // No room number
    }
};

std::string getEnvVar(const std::string &key) {
    const char *val = std::getenv(key.c_str());
    return val == nullptr ? std::string() : std::string(val);
}

bool authenticate(const std::string &token) {
    std::string secureToken = getEnvVar("SECURE_TOKEN");
    return token == secureToken;
}

bool isValidName(const std::string &name) {
    return !name.empty() && std::all_of(name.begin(), name.end(), ::isalpha) && name.length() <= 50;
}

bool appendLog(const std::string &logFile, const LogEntry &entry) {
    std::ofstream file(logFile, std::ios::app);
    if (!file) {
        std::cerr << "Error: Failed to open log file for appending: " << logFile << std::endl;
        return false;
    }

    file << entry.toString() << std::endl; // Log entry without room number
    return true;
}

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
                if (i + 1 < argc) {
                    token = argv[++i];
                }
            } else if (arg == "-E") {
                if (i + 1 < argc) {
                    personName = argv[++i];
                    if (!isValidName(personName)) {
                        std::cerr << "Invalid name" << std::endl;
                        return 1;
                    }
                }
            } else if (arg == "-G") {
                if (i + 1 < argc) {
                    personName = "Guest_" + std::string(argv[++i]); // Prefix guest names
                    if (!isValidName(personName.substr(6))) { // Validate without prefix
                        std::cerr << "Invalid guest name" << std::endl;
                        return 1;
                    }
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

    if (!authenticate(token)) {
        std::cerr << "Authentication failed" << std::endl;
        return 2;
    }

    LogEntry newEntry = {timestamp, action, personName};

    if (!appendLog(logFile, newEntry)) {
        std::cerr << "Failed to append log entry" << std::endl;
        return 1;
    }

    std::cout << "Log entry added." << std::endl;
    return 0;
}