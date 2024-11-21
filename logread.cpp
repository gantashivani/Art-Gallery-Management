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

bool authenticate(const std::string &token) {
    std::string secureToken = getEnvVar("SECURE_TOKEN");
    return token == secureToken;
}

bool readLog(std::vector<LogEntry> &entries, const std::string &logFile) {
    std::ifstream file(logFile);
    if (!file) {
        std::cerr << "Log file does not exist or cannot be opened: " << logFile << std::endl;
        return false;
    }

    std::string timestampStr, action, person;
    std::time_t timestamp;

    while (file >> timestampStr >> action >> person) {
        std::tm tm = {};
        std::istringstream ss(timestampStr);
        ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S");

        if (ss.fail()) {
            std::cerr << "Failed to parse timestamp: " << timestampStr << std::endl;
            continue;
        }

        timestamp = std::mktime(&tm);

        if (action != "enter" && action != "leave") {
            std::cerr << "Invalid action in log entry: " << action << std::endl;
            continue;
        }

        entries.emplace_back(timestamp, action, person);
    }
    return true;
}

void printCurrentState(const std::vector<LogEntry> &entries) {
    std::set<std::string> employeesInGallery;
    std::set<std::string> guestsInGallery;

    for (const auto &entry : entries) {
        if (entry.action == "enter") {
            // Check for guest prefix
            if (entry.person.find("Guest_") == 0) {
                guestsInGallery.insert(entry.person.substr(6)); // Remove prefix for display
            } else {
                employeesInGallery.insert(entry.person);
            }
        } else if (entry.action == "leave") {
            if (entry.person.find("Guest_") == 0) {
                guestsInGallery.erase(entry.person.substr(6)); // Remove prefix for display
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

    if (!authenticate(token)) {
        std::cerr << "Authentication failed: invalid token" << std::endl;
        return 2;
    }

    std::vector<LogEntry> entries;
    if (!readLog(entries, logFile)) {
        std::cerr << "Failed to read log file: " << logFile << std::endl;
        return 1;
    }

    printCurrentState(entries);
    return 0;
}