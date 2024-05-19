package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleUpload(t *testing.T) {
	// Set the storage directory in the config
	config.Storage = "files"
	config.Port = 8080
	config.BaseURL = "localhost"

	// Define the nested directory structure
	nestedDirs := []string{"folder1", "folder2", "folder3"}

	// Construct the expected directory structure in the upload path
	uploadPath := filepath.Join(append([]string{config.Storage}, nestedDirs...)...)

	// Create nested directories if they don't exist
	err := os.MkdirAll(uploadPath, os.ModePerm)
	if err != nil {
		t.Fatalf("Failed to create nested directories: %s", err)
	}
	defer os.RemoveAll(uploadPath)

	// Create a temporary file for testing
	tempFile, err := os.CreateTemp(uploadPath, "test-file-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tempFile.Name())

	// Write some content to the temporary file
	content := []byte("Test file content")
	if _, err := tempFile.Write(content); err != nil {
		t.Fatalf("Failed to write content to temporary file: %s", err)
	}
	tempFile.Close()

	// Create a ZIP archive from the temporary file
	zipPath := filepath.Join(uploadPath, "test-file.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create ZIP archive: %s", err)
	}
	defer os.Remove(zipPath)
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	fileWriter, err := zipWriter.Create(filepath.Base(tempFile.Name()))
	if err != nil {
		t.Fatalf("Failed to create ZIP file entry: %s", err)
	}

	tempFile, err = os.Open(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to open temporary file: %s", err)
	}
	defer tempFile.Close()

	_, err = io.Copy(fileWriter, tempFile)
	if err != nil {
		t.Fatalf("Failed to write to ZIP file: %s", err)
	}

	// Create a new HTTP request with the temporary file
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test-file.zip")
	if err != nil {
		t.Fatalf("Failed to create form file: %s", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Failed to write content to form file: %s", err)
	}
	writer.Close()

	// Construct the URL path with the nested directories
	urlPath := "/" + filepath.Join(nestedDirs...)

	// Create a request with explodeArchive set to true
	req, err := http.NewRequest("PUT", urlPath, body)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Explode-Archive", "true")

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handleUpload function
	handleUpload(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusCreated)
	}

	// Expected URI
	baseURI := fmt.Sprintf("%s:%d", config.BaseURL, config.Port)
	expectedURI := fmt.Sprintf("https://%s%s/%s", baseURI, urlPath, filepath.Base(zipPath))

	// Construct the expected response struct
	expected := struct {
		Status    int    `json:"status"`
		Message   string `json:"message"`
		Checksums struct {
			SHA256 string `json:"sha256"`
		} `json:"checksums"`
		URI      string `json:"uri"`
		Exploded bool   `json:"exploded"`
	}{
		Status:  http.StatusCreated,
		Message: "Created",
		Checksums: struct {
			SHA256 string `json:"sha256"`
		}{
			SHA256: "",
		},
		URI:      expectedURI,
		Exploded: true,
	}

	// Marshal the expected struct to JSON
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected JSON: %s", err)
	}

	// Check if the response body matches the expected JSON
	if strings.TrimSpace(rr.Body.String()) != string(expectedJSON) {
		t.Errorf("Handler returned unexpected body: got %v, expected %v", strings.TrimSpace(rr.Body.String()), string(expectedJSON))
	}

	// Check if the file was uploaded successfully to the expected path
	uploadedFilePath := filepath.Join(uploadPath, filepath.Base(tempFile.Name()))
	if _, err := os.Stat(uploadedFilePath); os.IsNotExist(err) {
		t.Errorf("Uploaded file does not exist: %s", uploadedFilePath)
	}

	// Create a request with explodeArchive set to false
	req, err = http.NewRequest("PUT", urlPath, body)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Explode-Archive", "false")

	// Reset the response recorder
	rr = httptest.NewRecorder()

	// Call the handleUpload function again
	handleUpload(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusCreated)
	}

	// Check if the response body matches the expected JSON
	if strings.TrimSpace(rr.Body.String()) != string(expectedJSON) {
		t.Errorf("Handler returned unexpected body: got %v, expected %v", strings.TrimSpace(rr.Body.String()), string(expectedJSON))
	}

	// Check if the file was uploaded successfully to the expected path
	if _, err := os.Stat(uploadedFilePath); os.IsNotExist(err) {
		t.Errorf("Uploaded file does not exist: %s", uploadedFilePath)
	}
}

func TestHandleDownload(t *testing.T) {
	config.Storage = `files`
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("files", "test-file-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tempFile.Name())

	// Write some content to the temporary file
	content := []byte("Test file content")
	if _, err := tempFile.Write(content); err != nil {
		t.Fatalf("Failed to write content to temporary file: %s", err)
	}
	tempFile.Close()

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/"+filepath.Base(tempFile.Name()), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handleDownload function
	handleDownload(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusOK)
	}

	// Check the response body
	if rr.Body.String() != string(content) {
		t.Errorf("Handler returned unexpected body: got %v, expected %v", rr.Body.String(), string(content))
	}

	// Check the response headers
	expectedContentDisposition := "attachment; filename=" + tempFile.Name()
	if contentDisposition := rr.Header().Get("Content-Disposition"); contentDisposition != expectedContentDisposition {
		t.Errorf("Handler returned unexpected Content-Disposition header: got %v, expected %v", contentDisposition, expectedContentDisposition)
	}

	expectedContentType := "application/octet-stream"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("Handler returned unexpected Content-Type header: got %v, expected %v", contentType, expectedContentType)
	}
	checksum := calculateSHA256(tempFile.Name())
	expectedDigest := fmt.Sprintf("sha-256=%s", checksum)
	if digest := rr.Header().Get("Digest"); digest != expectedDigest {
		t.Errorf("Handler returned unexpected Content-Type header: got %v, expected %v", digest, expectedDigest)
	}
}

func TestHandleFileList(t *testing.T) {
	config.Storage = `files`
	// Clean up the "files" directory before running the test
	err := os.RemoveAll("files")
	if err != nil {
		t.Fatalf("Failed to clean up files directory: %s", err)
	}
	err = os.MkdirAll("files", os.ModePerm)
	if err != nil {
		t.Fatalf("Failed to create files directory: %s", err)
	}

	// Create temporary files for testing
	tempFiles := []string{"test-file-1.txt", "test-file-2.txt", "test-file-3.txt"}
	for _, fileName := range tempFiles {
		tempFile, err := os.CreateTemp("files", fileName)
		if err != nil {
			t.Fatalf("Failed to create temporary file: %s", err)
		}
		tempFile.Close()
		defer os.Remove(tempFile.Name())
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/files", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handleFileList function
	handleFileList(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusOK)
	}

	// Check the response body
	var fileInfos []FileInfo
	err = json.Unmarshal(rr.Body.Bytes(), &fileInfos)
	if err != nil {
		t.Errorf("Failed to unmarshal response body: %s", err)
	}

	if len(fileInfos) != len(tempFiles) {
		t.Errorf("Handler returned unexpected number of files: got %v, expected %v", len(fileInfos), len(tempFiles))
	}

	for _, fileInfo := range fileInfos {
		if !strings.HasPrefix(fileInfo.Name, "test-file-") {
			t.Errorf("Handler returned unexpected file name: %s", fileInfo.Name)
		}
	}
}

func TestHandleDelete(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("files", "test-file-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tempFile.Name())

	// Create a new HTTP request
	req, err := http.NewRequest("DELETE", "/"+filepath.Base(tempFile.Name()), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handleDelete function
	handleDelete(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusOK)
	}

	// Construct the expected response struct
	expected := struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
		File    string `json:"file"`
	}{
		Status:  http.StatusOK,
		Message: "Deleted",
		File:    filepath.Base(tempFile.Name()),
	}

	// Marshal the expected struct to JSON
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected JSON: %s", err)
	}

	// Check if the response body matches the expected JSON
	if strings.TrimSpace(rr.Body.String()) != string(expectedJSON) {
		t.Errorf("Handler returned unexpected body: got %v, expected %v", strings.TrimSpace(rr.Body.String()), string(expectedJSON))
	}

	// Check if the file was deleted successfully
	if _, err := os.Stat(tempFile.Name()); !os.IsNotExist(err) {
		t.Errorf("File was not deleted successfully")
	}
}

func TestAuthMiddleware(t *testing.T) {
	// Create a test handler that requires authentication
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the test handler with the authMiddleware
	authHandler := authMiddleware(testHandler)

	// Create a new HTTP request without authentication
	reqWithoutAuth, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}

	// Create a response recorder
	rrWithoutAuth := httptest.NewRecorder()

	// Call the authHandler with the request without authentication
	authHandler.ServeHTTP(rrWithoutAuth, reqWithoutAuth)

	// Check the response status code (should be StatusUnauthorized)
	if status := rrWithoutAuth.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusUnauthorized)
	}

	// Create a new HTTP request with incorrect authentication
	reqWithIncorrectAuth, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %s", err)
	}
	reqWithIncorrectAuth.SetBasicAuth("invaliduser", "invalidpassword")

	// Create a response recorder
	rrWithIncorrectAuth := httptest.NewRecorder()

	// Call the authHandler with the request with incorrect authentication
	authHandler.ServeHTTP(rrWithIncorrectAuth, reqWithIncorrectAuth)

	// Check the response status code (should be StatusUnauthorized)
	if status := rrWithIncorrectAuth.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusUnauthorized)
	}

}

func TestErrorMiddleware(t *testing.T) {
	// Mock HTTP handler that panics
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Call the errorMiddleware with the mock handler
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	errorMiddleware(mockHandler).ServeHTTP(w, r)

	// Check the response status code
	if status := w.Code; status != http.StatusInternalServerError {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusInternalServerError)
	}

	// Check the response body
	expected := "Internal Server Error"
	actual := strings.TrimSpace(w.Body.String())
	if actual != expected {
		t.Errorf("Handler returned unexpected body: got %v, expected %v", actual, expected)
	}
}

func TestCalculateSHA256(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test-file-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tempFile.Name())

	// Write some content to the temporary file
	content := []byte("Test file content")
	if _, err := tempFile.Write(content); err != nil {
		t.Fatalf("Failed to write content to temporary file: %s", err)
	}
	tempFile.Close()

	// Calculate the SHA256 hash of the temporary file
	calculatedHash := calculateSHA256(tempFile.Name())

	// Expected SHA256 hash (calculated using external tool or known algorithm)
	expectedHash := "6c76f7bd4b84eb68c26d2e8f48ea76f90b9bdf8836e27235a0ca4325f8fe4ce5"

	// Compare the calculated hash with the expected hash
	if calculatedHash != expectedHash {
		t.Errorf("Calculated SHA256 hash does not match the expected hash: got %s, expected %s", calculatedHash, expectedHash)
	}
}

func TestAuthenticateUser(t *testing.T) {
	// Create a temporary users file for testing
	usersJSON := `[{"username": "user1", "password": "$argon2id$v=19$m=65536,t=1,p=4$269e5f62e25fc34809298e0f45a12058$1d36153d33b56e29b0dfb53753a648b077a544b2d1e30845d6bd0960ece4f7cd"}]`
	tempFile, err := os.CreateTemp("", "test-users-*.json")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tempFile.Name())
	if _, err := tempFile.WriteString(usersJSON); err != nil {
		t.Fatalf("Failed to write to temporary file: %s", err)
	}
	tempFile.Close()

	// Store the temporary file path in the config
	config.UserFile = tempFile.Name()

	// Test case: Valid username and password
	if !authenticateUser("user1", "password123") {
		t.Error("Failed to authenticate valid user")
	}

	// Test case: Invalid username
	if authenticateUser("invaliduser", "password123") {
		t.Error("Authenticated invalid username")
	}

	// Test case: Invalid password
	if authenticateUser("user1", "invalidpassword") {
		t.Error("Authenticated invalid password")
	}
}

func TestVerifyPassword(t *testing.T) {
	// Define test cases
	testCases := []struct {
		username       string
		password       string
		hashedPassword string
		expectedResult bool
	}{
		// Correct password verification
		{"user1", "password123", "$argon2id$v=19$m=65536,t=1,p=4$269e5f62e25fc34809298e0f45a12058$1d36153d33b56e29b0dfb53753a648b077a544b2d1e30845d6bd0960ece4f7cd", true},
		// Incorrect password verification
		{"user2", "wrongpassword", "$argon2id$v=19$m=65536,t=1,p=4$269e5f62e25fc34809298e0f45a12058$1d36153d33b56e29b0dfb53753a648b077a544b2d1e30845d6bd0960ece4f7cd", false},
		// Invalid hashed password format
		{"user3", "password123", "invalidformat", false},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Username: %s", tc.username), func(t *testing.T) {
			result := verifyPassword(tc.password, tc.hashedPassword)
			if result != tc.expectedResult {
				t.Errorf("Verification failed for username %s: expected %t, got %t", tc.username, tc.expectedResult, result)
			}
		})
	}
}
