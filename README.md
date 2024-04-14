# Disclaimer

**It is a hobby project for me to toy around with go and build some CI/CD Pipelines for go projects.\
This ships "as-is", there will be no support, use at own risk, etc.**

# Go Simple File Server: go-sfs

This Go project implements a simple file server with authentication, rate limiting, and daemon mode support.

## Features

- **Authentication**: Users can authenticate using basic authentication with a username and password.
- **Rate Limiting**: Requests are rate-limited to prevent abuse.
- **Daemon Mode**: Supports running as a daemon process.
- **HTTPS Support**: The server runs over HTTPS with self-signed certificates.
- **File Upload/Download**: Users can upload and download files securely.

## Getting Started

### Configuration

The server can be configured via a JSON configuration file located at `./config/config.json`. You can modify the configuration according to your requirements.

If you're not providing a config a default config will be created:

```json
{
  "rateLimit": {
    "requestsPerSecond": 1,
    "burst": 5
  },
  "daemon": {
    "pidFile": "./config/pid",
    "logFile": "./config/log"
  },
  "port": 8080,
  "userFile": "./config/users.json",
  "storage": "./data",
  "certFolder": "./config/certs"
}
```

### Docker

#### Docker Compose Example

You can also use Docker Compose to manage your file server container. Here's an example `docker-compose.yml` file:

```yaml
version: '3'

services:
  go-sfs:
    image: mietzen/go-sfs
    container_name: go-sfs
    ports:
      - "8080:8080"
    volumes:
      - ./config:/config
      - ./data:/data
    environment:
      # - USER_FILE=/config/users.json
      # - STORAGE=/data
      # - CERTS=/config/certs
      - LIMITER_REQUESTS_PER_SECOND=1
      - LIMITER_BURST=5
      - PORT=8080
```

Save this file as `docker-compose.yml` in your project directory, then run the following command:

```bash
docker-compose up -d
```

This will start the file server container in detached mode, using the configuration specified in the `docker-compose.yml` file.

Now you can access your file server at `http://localhost:8080`.

You can also override the configuration values using environment variables in the `docker-compose.yml` file as shown above.

##### Adding a User

To add a new user, use the `-u` flag followed by the username, and optionally the `-p` flag followed by the password:

```bash
docker exec go-sfs /go-sfs -u username
```

#### Building the Docker Image yourself

To build the Docker image for the file server, navigate to the directory containing your Dockerfile and execute the following command:

```bash
docker build -t go-sfs .
```

### Binary

#### Download

You can Download the latest Binary here:

[https://github.com/mietzen/go-sfs/releases/latest](https://github.com/mietzen/go-sfs/releases/latest)

or build it yourself.

#### Build

1. Clone this repository:

   ```bash
   git clone https://github.com/mietzen/go-sfs.git
   ```

2. Navigate to the project directory:

   ```bash
   cd project-directory
   ```

3. Build the project:

   ```bash
   go build
   ```

4. Test the project:

   ```bash
   go test
   ```

#### Running the Server

To run the server, execute the built executable:

```bash
./go-sfs
```

#### Environment

You can use the following environment variables to overwrite settings:

- USER_FILE=/config/users.json
- STORAGE=/data
- CERTS=/config/certs
- LIMITER_REQUESTS_PER_SECOND=1
- LIMITER_BURST=5
- PORT=8080

#### Adding a User

To add a new user, use the `-u` flag followed by the username, and optionally the `-p` flag followed by the password:

```bash
./go-sfs -u username -p password
```

#### Running in Daemon Mode

To run the server in daemon mode, use the `-d` flag:

```bash
./go-sfs -d
```

## Usage

### API Endpoints & Examples

- **Upload File**: `PUT /upload/{path}`
  - Upload a file to the specified path.
- **Download File**: `GET /download/{path}`
  - Download a file from the specified path.
- **List Files**: `GET /files`
  - List all files available for download.
- **Delete File**: `DELETE /delete/{path}`
  - Delete a file from the specified path.

#### Upload a File

```bash
curl -u username:password -X PUT -T "path/to/local/file" http://localhost:8080/upload/path/to/remote/file
```

#### Download a File

```bash
curl -u username:password -OJ http://localhost:8080/download/path/to/file
```

#### List Files

```bash
curl -u username:password http://localhost:8080/files
```

#### Delete a File

```bash
curl -u username:password -X DELETE http://localhost:8080/delete/path/to/file
```

Replace `username`, `password`, `path/to/local/file`, and `path/to/remote/file` with appropriate values.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
