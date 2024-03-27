package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sevlyar/go-daemon"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"golang.org/x/time/rate"
)

type FileInfo struct {
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
	UserFile string `json:"userFile"`
	Storage  string `json:"storage"`
}

var (
	limiter *rate.Limiter
	config  Config
)

func main() {
	// Parse command-line flags
	usernameFlag := flag.String("u", "", "Username to add")
	passwordFlag := flag.String("p", "", "Password for the user")
	daemonFlag := flag.Bool("d", false, "Run in daemon mode")
	flag.Parse()

	// Read the configuration from config.json
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Error opening config file: %s\n", err)
	}
	defer configFile.Close()

	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s\n", err)
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

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := header.Filename
	dst, err := os.Create(filepath.Join(config.Storage, filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username, ok := r.Context().Value("username").(string)
	if !ok {
		log.Println("Failed to retrieve username from context")
		username = "Unknown"
	}

	log.Printf("File uploaded: %s by user: %s\n", filename, username)
	fmt.Fprintf(w, "File uploaded successfully")
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := filepath.Base(r.URL.Path)
	filePath := filepath.Join(config.Storage, filename)

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
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, file)
}

func handleFileList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := os.ReadDir(config.Storage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(config.Storage, file.Name())
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			hash := calculateSHA256(filePath)

			fileInfos = append(fileInfos, FileInfo{
				Name:       file.Name(),
				UploadDate: fileInfo.ModTime(),
				Size:       fileInfo.Size(),
				SHA256:     hash,
			})
		}
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

	// Extract filename from URL
	filename := filepath.Base(r.URL.Path)
	filePath := filepath.Join(config.Storage, filename)

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Delete the file
	if err := os.Remove(filePath); err != nil {
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
	data, err := os.ReadFile("users")
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
	err = os.WriteFile("users", data, 0644)
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

	http.HandleFunc("/upload", errorMiddleware(rateLimitMiddleware(authMiddleware(handleUpload))))
	http.HandleFunc("/download/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDownload))))
	http.HandleFunc("/files", errorMiddleware(rateLimitMiddleware(authMiddleware(handleFileList))))
	http.HandleFunc("/delete/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDelete))))
	log.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
