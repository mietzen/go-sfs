package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(1, 5) // Allow 1 request per second with a burst of 5

type FileInfo struct {
	Name       string    `json:"name"`
	UploadDate time.Time `json:"uploadDate"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
}

func main() {
	http.HandleFunc("/upload", errorMiddleware(rateLimitMiddleware(authMiddleware(handleUpload))))
	http.HandleFunc("/download/", errorMiddleware(rateLimitMiddleware(authMiddleware(handleDownload))))
	http.HandleFunc("/files", errorMiddleware(rateLimitMiddleware(authMiddleware(handleFileList))))

	log.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
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

	log.Printf("File uploaded: %s\n", filename)
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

	log.Printf("File downloaded: %s\n", filename)
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

	log.Println("File list requested")
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

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "your_username" || password != "your_password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
