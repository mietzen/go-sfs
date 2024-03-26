package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
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
}

var limiter *rate.Limiter

func main() {
	// Read the configuration from config.json
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Error opening config file: %s\n", err)
	}
	defer configFile.Close()

	var config Config
	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s\n", err)
	}

	// Create the rate limiter with the configured values
	limiter = rate.NewLimiter(rate.Limit(config.RateLimit.RequestsPerSecond), config.RateLimit.Burst)

	// Create the "files" folder if it doesn't exist
	err = os.MkdirAll("files", os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating files folder: %s\n", err)
	}

	http.HandleFunc("/upload", errorMiddleware(rateLimitMiddleware(authMiddleware(handleUpload))))
	http.HandleFunc("/download/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDownload))))
	http.HandleFunc("/files", errorMiddleware(rateLimitMiddleware(authMiddleware(handleFileList))))

	log.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
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
	dst, err := os.Create(filepath.Join("files", filename))
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

	username := r.Context().Value("username").(string)
	log.Printf("File uploaded: %s by user: %s\n", filename, username)
	fmt.Fprintf(w, "File uploaded successfully")
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := filepath.Base(r.URL.Path)
	filePath := filepath.Join("files", filename)

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	username := r.Context().Value("username").(string)
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

	files, err := os.ReadDir("files")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join("files", file.Name())
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

	username := r.Context().Value("username").(string)
	log.Printf("File list requested by user: %s\n", username)
	json.NewEncoder(w).Encode(fileInfos)
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
	data, err := os.ReadFile("users")
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
	// Extract the salt and key from the hashed password
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 4 {
		return false
	}

	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}

	key, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}

	// Compute the Argon2 hash of the provided password with the same parameters
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Compare the computed hash with the stored key
	return subtle.ConstantTimeCompare(key, hash) == 1
}
