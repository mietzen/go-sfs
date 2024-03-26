# File Server

A simple file server implemented in Go that allows users to upload, download, and list files. The server supports authentication using username and password, rate limiting, and secure storage of user credentials.

## Features

- Upload files using a PUT request
- Download files using a GET request
- List all uploaded files with their details (name, upload date, size, and SHA256 hash) using a GET request
- User authentication using Basic Auth
- User credentials stored securely as Argon2 hashes
- Rate limiting to prevent excessive requests
- Logging of file operations with username
- Automatic creation of "files" folder if it doesn't exist

## Prerequisites

- Go 1.16 or later
- `golang.org/x/crypto/argon2` package

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
   ```

4. Build the project:
   ```
   go build
   ```

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

3. The server will start running on `http://localhost:8080`.

4. Use the following endpoints to interact with the file server:
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

## Configuration

- Rate Limiting:
  - The server is configured to allow 1 request per second with a burst of 5 requests.
  - Modify the `limiter` variable in the code to change the rate limiting settings.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE)