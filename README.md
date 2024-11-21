# Art Gallery Secure Log Manager

This is a secure log manager for an art gallery that tracks employee and guest entries and exits.

## Features
- Secure authentication using environment variables.
- Log entries for employees and guests.
- Read and append log entries with validation.

## Usage
### Log Append
To append a log entry, use:
logappend -K <token> -E <employee-name> -A -R <room-id> <log-file>


### Log Read
To read the log, use:
logread -K <token> <log-file>


## Installation
1. Ensure you have `g++` installed.
2. Clone the repository.
3. Compile the code:
   ```
   g++ -o logappend logappend.cpp
   g++ -o logread logread.cpp
   ```

## Environment Variables
- `SECURE_TOKEN`: Set this variable to the token used for authentication.

## Testing
Unit tests are recommended to ensure functionality. Consider using a testing framework like Google Test.

## License
This project is licensed under the MIT License.
