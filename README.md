# File Server

A simple file server implemented in Go that allows users to upload, download, and list files. The server supports authentication, rate limiting, secure storage of user credentials, and the ability to run as a daemon.

## Features

- Upload files using a PUT request
- Download files using a GET request
- List all uploaded files with their details (name, upload date, size, and SHA256 hash) using a GET request
- User authentication using Basic Auth
- User credentials stored securely as Argon2 hashes
- Rate limiting to prevent excessive requests
- Logging of file operations with username
- Ability to run as a daemon in the background
- Configuration options for rate limiting and daemon settings
- Automatic creation of "files" folder if it doesn't exist
- Command-line options for adding users and running in daemon mode

## Prerequisites

- Go 1.16 or later
- `golang.org/x/crypto/argon2` package
- `github.com/sevlyar/go-daemon` package

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/fileserver.git
   ```

2. Change to the project directory:
   ```
   cd fileserver
   ```

3. Install the required dependencies:
   ```
   go get golang.org/x/crypto/argon2
   go get github.com/sevlyar/go-daemon
   ```

4. Build the project:
   ```
   go build
   ```

## Configuration

The server can be configured using a JSON configuration file named `config.json`. The configuration file should be placed in the same directory as the server binary. Here's an example configuration:

```json
{
  "rateLimit": {
    "requestsPerSecond": 1,
    "burst": 5
  },
  "daemon": {
    "pidFile": "fileserver.pid",
    "logFile": "fileserver.log"
  }
}
```

- `rateLimit`: Settings for rate limiting.
  - `requestsPerSecond`: The maximum number of requests allowed per second.
  - `burst`: The maximum number of requests allowed to exceed the rate limit in a single burst.
- `daemon`: Settings for running the server as a daemon.
  - `pidFile`: The path to the file where the daemon's process ID will be stored.
  - `logFile`: The path to the file where the daemon's logs will be written.

## Usage

1. Create a `users` file in the project directory containing the user credentials in JSON format:
   ```json
   [
     {
       "username": "user1",
       "password": "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$hash"
     },
     {
       "username": "user2",
       "password": "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$hash"
     }
   ]
   ```
   Replace `"user1"` and `"user2"` with the desired usernames and `"$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$hash"` with the actual Argon2 hashed passwords.

2. Run the server:
   ```
   ./fileserver
   ```

3. To add a new user, use the `-u` flag followed by the username. You can optionally provide the password using the `-p` flag. If the password is not provided, you will be prompted to enter it.
   ```
   ./fileserver -u newuser -p password
   ```
   or
   ```
   ./fileserver -u newuser
   Password: ********
   ```

4. To run the server as a daemon, use the `-d` flag:
   ```
   ./fileserver -d
   ```

5. The server will start running on `http://localhost:8080`.

6. Use the following endpoints to interact with the file server:
   - Upload a file:
     ```
     curl -u username:password -X PUT -F "file=@/path/to/file" http://localhost:8080/upload
     ```
   - Download a file:
     ```
     curl -u username:password -O http://localhost:8080/download/filename
     ```
   - List all files:
     ```
     curl -u username:password http://localhost:8080/files
     ```

   Replace `username` and `password` with the appropriate credentials, `/path/to/file` with the path to the file you want to upload, and `filename` with the name of the file you want to download.

## Running Tests

The project includes a set of test cases to verify the functionality of the file server. To run the tests, use the following command:

```
go test
```

The tests cover various scenarios, including file upload, download, listing, and authentication.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).