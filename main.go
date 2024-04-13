package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sevlyar/go-daemon"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"golang.org/x/time/rate"
)

type FileInfo struct {
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	UploadDate time.Time `json:"uploadDate"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	RateLimit struct {
		RequestsPerSecond int `json:"requestsPerSecond"`
		Burst             int `json:"burst"`
	} `json:"rateLimit"`
	Daemon struct {
		PidFile string `json:"pidFile"`
		LogFile string `json:"logFile"`
	} `json:"daemon"`
	Port       int    `json:"port"`
	UserFile   string `json:"userFile"`
	Storage    string `json:"storage"`
	CertFolder string `json:"certFolder"`
}

var (
	limiter *rate.Limiter
	config  Config
)

const (
	defaultConfigFile = "./config/config.json"
	defaultPort       = 8080
)

func main() {
	// Parse command-line flags
	usernameFlag := flag.String("u", "", "Username to add")
	passwordFlag := flag.String("p", "", "Password for the user")
	daemonFlag := flag.Bool("d", false, "Run in daemon mode")
	flag.Parse()

	// Read the configuration from config.json
	if _, err := os.Stat(defaultConfigFile); os.IsNotExist(err) {
		// Config file does not exist, create it with default values
		createDefaultConfig()
	}

	// Read the configuration from config.json
	configFile, err := os.Open(defaultConfigFile)
	if err != nil {
		log.Fatalf("Error opening config file: %s\n", err)
	}
	defer configFile.Close()

	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s\n", err)
	}

	// Override configuration values with environment variables if set
	if userFile := os.Getenv("USER_FILE"); userFile != "" {
		config.UserFile = userFile
	}
	if storage := os.Getenv("STORAGE"); storage != "" {
		config.Storage = storage
	}
	if certFolder := os.Getenv("CERTS"); certFolder != "" {
		config.CertFolder = certFolder
	}
	if requestsPerSecond := os.Getenv("LIMITER_REQUESTS_PER_SECOND"); requestsPerSecond != "" {
		if rps, err := strconv.Atoi(requestsPerSecond); err == nil {
			config.RateLimit.RequestsPerSecond = rps
		}
	}
	if burst := os.Getenv("LIMITER_BURST"); burst != "" {
		if b, err := strconv.Atoi(burst); err == nil {
			config.RateLimit.Burst = b
		}
	}
	if serverPort := os.Getenv("PORT"); serverPort != "" {
		port, err := strconv.Atoi(serverPort)
		if err == nil {
			config.Port = port
		}
	}

	// Create the rate limiter with the configured values
	limiter = rate.NewLimiter(rate.Limit(config.RateLimit.RequestsPerSecond), config.RateLimit.Burst)

	// Check if the -u flag is provided
	if *usernameFlag != "" {
		addUser(*usernameFlag, *passwordFlag)
		return
	}

	// Check if the -d flag is provided
	if *daemonFlag {
		daemonize()
		return
	}

	// Start the server
	startServer()
}

func createDefaultConfig() {
	// Create default configuration
	config := Config{
		RateLimit: struct {
			RequestsPerSecond int `json:"requestsPerSecond"`
			Burst             int `json:"burst"`
		}{
			RequestsPerSecond: 1,
			Burst:             5,
		},
		Daemon: struct {
			PidFile string `json:"pidFile"`
			LogFile string `json:"logFile"`
		}{
			PidFile: "./config/pid",
			LogFile: "./config/log",
		},
		Port:       defaultPort,
		UserFile:   "./config/users.json",
		Storage:    "./data",
		CertFolder: "./config/certs",
	}

	// Marshal the default configuration to JSON
	configData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		log.Fatalf("Error marshaling default config: %s\n", err)
	}

	// Write the default configuration to config.json
	err = os.WriteFile(defaultConfigFile, configData, 0644)
	if err != nil {
		log.Fatalf("Error writing default config to file: %s\n", err)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the provided username and password match the stored credentials
		if !authenticateUser(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add the username to the request context for logging
		r = r.WithContext(context.WithValue(r.Context(), "username", username))

		next(w, r)
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func errorMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next(w, r)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the URL path to extract the directory structure
	urlParts := strings.Split(r.URL.Path, "/")
	// Remove the first element which is an empty string
	urlParts = urlParts[2:]

	// Construct the directory path from URL parts
	uploadPath := filepath.Join(urlParts...)

	// Append the file name to the directory path
	filePath := filepath.Join(config.Storage, uploadPath)

	isValid, err := isValidPath(filePath, config.Storage)
	if err != nil {
		log.Fatalf("Error validating path: %s\n", err)
		return
	}

	if !isValid {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Create directories recursively if they don't exist
	err = os.MkdirAll(filePath, os.ModePerm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the file from the request
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create the destination file
	dst, err := os.Create(filepath.Join(filePath, header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the file contents
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the username from the request context
	username, ok := r.Context().Value("username").(string)
	if !ok {
		log.Println("Failed to retrieve username from context")
		username = "Unknown"
	}

	// Log the upload details
	log.Printf("File uploaded: %s by user: %s\n", header.Filename, username)
	fmt.Fprintf(w, "File uploaded successfully")
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the URL path to extract the directory structure
	urlParts := strings.Split(r.URL.Path, "/")
	// Remove the first element which is an empty string
	urlParts = urlParts[2:]

	// Construct the directory path from URL parts
	uploadPath := filepath.Join(urlParts...)

	// Append the file name to the directory path
	filePath := filepath.Join(config.Storage, uploadPath)
	filename := filepath.Base(filePath)

	isValid, err := isValidPath(filePath, config.Storage)
	if err != nil {
		log.Fatalf("Error validating path: %s\n", err)
		return
	}

	if !isValid {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	username, ok := r.Context().Value("username").(string)
	if !ok {
		log.Println("Failed to retrieve username from context")
		username = "Unknown"
	}

	log.Printf("File downloaded: %s by user: %s\n", filename, username)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filePath))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, file)
}

// handleFileList function with base directory removed from the path
func handleFileList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseFolder := filepath.Base(config.Storage)

	var fileInfos []FileInfo
	err := filepath.Walk(config.Storage, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relativePath := strings.TrimPrefix(path, baseFolder)
			relativePath = strings.TrimPrefix(relativePath, "/")
			hash := calculateSHA256(path)
			fileInfos = append(fileInfos, FileInfo{
				Path:       relativePath,
				Name:       info.Name(),
				UploadDate: info.ModTime(),
				Size:       info.Size(),
				SHA256:     hash,
			})
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username, ok := r.Context().Value("username").(string)
	if !ok {
		log.Println("Failed to retrieve username from context")
		username = "Unknown"
	}

	log.Printf("File list requested by user: %s\n", username)
	json.NewEncoder(w).Encode(fileInfos)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the URL path to extract the directory structure
	urlParts := strings.Split(r.URL.Path, "/")
	// Remove the first element which is an empty string
	urlParts = urlParts[2:]

	// Construct the directory path from URL parts
	uploadPath := filepath.Join(urlParts...)

	// Append the file name to the directory path
	filePath := filepath.Join(config.Storage, uploadPath)
	filename := filepath.Base(filePath)

	isValid, err := isValidPath(filePath, config.Storage)
	if err != nil {
		log.Fatalf("Error validating path: %s\n", err)
		return
	}

	if !isValid {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Delete the file
	if err := os.RemoveAll(filePath); err != nil {
		http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	log.Printf("File deleted: %s\n", filename)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File deleted successfully"))
}

func calculateSHA256(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file for SHA256 calculation: %s\n", err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Printf("Error calculating SHA256: %s\n", err)
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func authenticateUser(username, password string) bool {
	// Read the users file
	data, err := os.ReadFile(config.UserFile)
	if err != nil {
		log.Printf("Error reading users file: %s\n", err)
		return false
	}

	// Parse the JSON data
	var users []User
	err = json.Unmarshal(data, &users)
	if err != nil {
		log.Printf("Error parsing users file: %s\n", err)
		return false
	}

	// Find the user with the matching username
	for _, user := range users {
		if user.Username == username {
			// Verify the password hash
			return verifyPassword(password, user.Password)
		}
	}

	return false
}

func verifyPassword(password, hashedPassword string) bool {
	// Extract the parameters and salt from the hashed password
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 {
		return false
	}

	var params []string
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params)

	salt, _ := hex.DecodeString(parts[4])
	key, _ := hex.DecodeString(parts[5])

	// Compute the Argon2 hash of the provided password with the same parameters and salt
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Compare the computed hash with the stored key
	return subtle.ConstantTimeCompare(key, hash) == 1
}

func addUser(username, password string) {
	// Read the existing users from the users file
	users, err := readUsers()
	if err != nil {
		log.Fatalf("Error reading users file: %s\n", err)
	}

	// Check if the user already exists
	for _, user := range users {
		if user.Username == username {
			fmt.Printf("User '%s' already exists. Do you want to overwrite the password? (y/n): ", username)
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" {
				fmt.Println("User not updated.")
				return
			}
			break
		}
	}

	// Prompt for password if not provided as a flag
	if password == "" {
		fmt.Print("Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Error reading password: %s\n", err)
		}
		password = string(passwordBytes)
		fmt.Println()
	}

	// Generate Argon2 hash of the password
	hashedPassword := generatePasswordHash(password)

	// Update or add the user
	updated := false
	for i, user := range users {
		if user.Username == username {
			users[i].Password = hashedPassword
			updated = true
			break
		}
	}
	if !updated {
		users = append(users, User{Username: username, Password: hashedPassword})
	}

	// Write the updated users to the users file
	err = writeUsers(users)
	if err != nil {
		log.Fatalf("Error writing users file: %s\n", err)
	}

	fmt.Printf("User '%s' %s successfully.\n", username, map[bool]string{true: "updated", false: "added"}[updated])
}

func readUsers() ([]User, error) {
	// Read the users file
	data, err := os.ReadFile(config.UserFile)
	if err != nil {
		// If the file doesn't exist, return an empty slice
		if os.IsNotExist(err) {
			return []User{}, nil
		}
		return nil, err
	}

	// Parse the JSON data
	var users []User
	err = json.Unmarshal(data, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func writeUsers(users []User) error {
	// Marshal the users to JSON
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}

	// Write the JSON data to the users file
	err = os.WriteFile(config.UserFile, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func generatePasswordHash(password string) string {
	// Generate a random salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatalf("Error generating salt: %s\n", err)
	}

	// Compute the Argon2 hash of the password
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Encode the salt and hash as a string
	hashedPassword := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%x$%x", argon2.Version, 64*1024, 1, 4, salt, hash)

	return hashedPassword
}

func daemonize() {
	// Create a new context for the daemon
	ctx := &daemon.Context{
		PidFileName: config.Daemon.PidFile,
		PidFilePerm: 0644,
		LogFileName: config.Daemon.LogFile,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        []string{"fileserver"},
	}

	// Create a child process
	child, err := ctx.Reborn()
	if err != nil {
		log.Fatalf("Failed to daemonize: %s\n", err)
	}

	if child != nil {
		// Parent process
		fmt.Println("File server is running in daemon mode.")
		os.Exit(0)
	} else {
		// Daemon process
		defer ctx.Release()

		// Start the server
		startServer()
	}
}

func startServer() {
	// Create the config.Storage folder if it doesn't exist
	err := os.MkdirAll(config.Storage, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating files folder: %s\n", err)
	}

	// Define the server address using the configured port
	serverAddr := fmt.Sprintf(":%d", config.Port)

	// Register the request handlers
	http.HandleFunc("/upload/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleUpload))))
	http.HandleFunc("/download/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDownload))))
	http.HandleFunc("/files", errorMiddleware(rateLimitMiddleware(authMiddleware(handleFileList))))
	http.HandleFunc("/delete/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDelete))))

	// Load SSL certificate and key
	certFile := filepath.Join(config.CertFolder, "server.crt")
	keyFile := filepath.Join(config.CertFolder, "server.key")

	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)

	if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
		log.Println("SSL certificate or key not found, generating self-signed certificates...")
		err := os.MkdirAll(config.CertFolder, os.ModePerm)
		if err != nil {
			log.Fatalf("Error creating files folder: %s\n", err)
		}
		err = generateSelfSignedCert(certFile, keyFile)
		if err != nil {
			log.Fatalf("Error generating self-signed certificates: %s\n", err)
		}
	}

	// Create HTTPS server
	server := &http.Server{
		Addr: serverAddr,
	}

	// Start the HTTPS server
	log.Printf("Server is running on https://localhost%s\n", serverAddr)
	err = server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error starting HTTPS server: %s\n", err)
	}
}

func generateSelfSignedCert(certFile, keyFile string) error {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return nil
}

func isValidPath(path string, baseDir string) (bool, error) {
	// Get the absolute path of the upload path
	absUploadPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Get the absolute path of the base directory
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return false, err
	}

	// Check if the upload path is within the base directory
	relPath, err := filepath.Rel(absBaseDir, absUploadPath)
	if err != nil {
		return false, err
	}

	if relPath == ".." || filepath.IsAbs(relPath) {
		// The upload path is trying to access files outside the base directory
		return false, nil
	}

	// The upload path is valid
	return true, nil
}
