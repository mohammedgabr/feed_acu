package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	// Store the expected MD5 hash for the password "Zalabia@9"
	expectedPasswordHash = "94cda1e5b3b0eb41e28b69e951d33242"
	// Profile ID for SQL Injection Vulnerabilities
	sqlInjectionProfileID = "11111111-1111-1111-1111-111111111113"
)

// Helper to sanitize URLs identically to JS
func normalizeTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return strings.ToLower(strings.TrimSuffix(target, "/"))
	}
	// Remove scheme, force to lower case, remove trailing slash
	return strings.ToLower(strings.TrimSuffix(u.Host+u.Path, "/"))
}

// Global Job Manager
var jobQueue = make(chan ScanJob, 10000)
var resultsStore = sync.Map{} // thread-safe map to store: targetURL -> ScanResult
var remoteActiveCount = 0
var lastRemoteSync time.Time
var syncMu sync.Mutex

var activeWorkers = 0
var maxWorkers = 10
var workerCountMu sync.Mutex
var activeMu sync.Mutex

type TargetRequest struct {
	Address     string `json:"address"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Criticality int    `json:"criticality"`
}

type ScanRequest struct {
	ProfileID string       `json:"profile_id"`
	TargetID  string       `json:"target_id"`
	Schedule  ScanSchedule `json:"schedule"`
}

type ScanSchedule struct {
	Disable       bool    `json:"disable"`
	StartDate     *string `json:"start_date"`
	TimeSensitive bool    `json:"time_sensitive"`
}

type ScanPayload struct {
	APIURL   string   `json:"api_url"`
	APIKey   string   `json:"api_key"`
	Targets  []string `json:"targets"`
	MaxScans int      `json:"max_scans"`
}

type ScanResult struct {
	Target  string `json:"target"`
	Status  string `json:"status"` // "Pending", "Running", "Success", "Failed"
	Message string `json:"message"`
}

type ScanJob struct {
	APIURL string
	APIKey string
	Target string
	Client *http.Client
}

func main() {
	// Start Worker Pool - initialize a large pool to handle spikes but throttle via maxWorkers dynamically
	for i := 0; i < 100; i++ {
		go worker()
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/scan/queue", queueHandler)
	http.HandleFunc("/api/scan/cancel", cancelHandler)
	http.HandleFunc("/api/scan/cancel-all", cancelAllHandler)
	http.HandleFunc("/api/scan/status", statusHandler)
	http.HandleFunc("/api/extract", extractHandler)
	http.HandleFunc("/api/acunetix/stats", acunetixStatsHandler)

	port := "8080"
	fmt.Printf("[+] Starting Acunetix Web Feeder with Worker Queue on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func worker() {
	for job := range jobQueue {
		// Wait if we are at/over the max limit
		cancelled := false
		for {
			syncMu.Lock()
			// If sync is older than 5 seconds, refresh it
			if time.Since(lastRemoteSync) > 5*time.Second {
				log.Println("[Worker] Syncing remote scan load before starting next job...")
				count, err := getRemoteScanCount(job.Client, job.APIURL, job.APIKey)
				if err == nil {
					remoteActiveCount = count
					lastRemoteSync = time.Now()
					log.Printf("[Worker] Remote sync complete. Total active scans: %d (Limit: %d)", remoteActiveCount, maxWorkers)
				} else {
					log.Printf("[Worker] Remote load check failed (possible Acunetix hang): %v. Waiting...", err)
				}
			}

			workerCountMu.Lock()
			if remoteActiveCount < maxWorkers {
				remoteActiveCount++
				workerCountMu.Unlock()
				syncMu.Unlock()
				break
			}
			workerCountMu.Unlock()
			syncMu.Unlock()

			// Check if target was cancelled while waiting
			if res, ok := resultsStore.Load(job.Target); ok {
				status := res.(ScanResult).Status
				if status == "Cancelled" {
					cancelled = true
					break
				}
			}

			time.Sleep(2 * time.Second)
		}

		if cancelled {
			continue
		}

		// Mark as running
		resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Running", Message: "Starting scan..."})

		// 1. Add Target
		tid, terr := addTarget(job.Client, job.APIURL, job.APIKey, job.Target)
		if terr != nil {
			resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: fmt.Sprintf("Add Target Error: %v", terr)})
		} else {
			// 2. Start Scan
			sid, serr := startScan(job.Client, job.APIURL, job.APIKey, tid)
			if serr != nil {
				resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: fmt.Sprintf("Start Scan Error: %v", serr)})
			} else {
				resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Running", Message: "Scan running in Acunetix..."})
				// 3. Poll Scan Status
				perr := pollScan(job.Client, job.APIURL, job.APIKey, sid)
				if perr != nil {
					resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: perr.Error()})
				} else {
					resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Success", Message: "Scan completed"})
				}
			}
		}

		// When a job finishes, we decrement remoteActiveCount to stay responsive
		syncMu.Lock()
		if remoteActiveCount > 0 {
			remoteActiveCount--
		}
		syncMu.Unlock()
	}
}

// Dedicated helper to count total active scans on Acunetix with pagination
func getRemoteScanCount(client *http.Client, apiURL, apiKey string) (int, error) {
	count := 0
	cursor := "0"
	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/scans?c=%s&l=100", apiURL, cursor), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Auth", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return 0, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Scans []struct {
				CurrentSession struct {
					Status string `json:"status"`
				} `json:"current_session"`
			} `json:"scans"`
			Pagination struct {
				Cursors []interface{} `json:"cursors"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return 0, err
		}
		resp.Body.Close()

		for _, s := range result.Scans {
			stat := strings.ToLower(s.CurrentSession.Status)
			// Statuses that consume an engine slot
			if stat == "processing" || stat == "starting" || stat == "queued" || stat == "running" || stat == "scheduled" {
				count++
			}
		}

		if len(result.Pagination.Cursors) > 0 && result.Pagination.Cursors[0] != nil {
			cursor = fmt.Sprintf("%v", result.Pagination.Cursors[0])
		} else {
			break
		}
	}
	return count, nil
}

func addTarget(client *http.Client, apiURL, apiKey, targetURL string) (string, error) {
	reqData := TargetRequest{
		Address:     targetURL,
		Description: "Added via Web Feeder Queue",
		Type:        "default",
		Criticality: 10,
	}

	payload, _ := json.Marshal(reqData)
	req, err := http.NewRequest("POST", apiURL+"/targets", bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("X-Auth", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Status %s: %s", resp.Status, string(bodyBytes))
	}

	var targetResp struct {
		TargetID string `json:"target_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targetResp); err != nil {
		return "", err
	}

	return targetResp.TargetID, nil
}

func startScan(client *http.Client, apiURL, apiKey, targetID string) (string, error) {
	reqData := ScanRequest{
		ProfileID: sqlInjectionProfileID,
		TargetID:  targetID,
		Schedule: ScanSchedule{
			Disable:       false,
			StartDate:     nil,
			TimeSensitive: false,
		},
	}

	payload, _ := json.Marshal(reqData)
	req, err := http.NewRequest("POST", apiURL+"/scans", bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("X-Auth", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Status %s: %s", resp.Status, string(bodyBytes))
	}

	var scanResp struct {
		ScanID string `json:"scan_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&scanResp)
	if scanResp.ScanID != "" {
		return scanResp.ScanID, nil
	}
	loc := resp.Header.Get("Location")
	if loc != "" {
		parts := strings.Split(loc, "/")
		return parts[len(parts)-1], nil
	}

	return "", fmt.Errorf("scan_id not found in response")
}

func pollScan(client *http.Client, apiURL, apiKey, scanID string) error {
	for {
		time.Sleep(10 * time.Second)

		req, err := http.NewRequest("GET", apiURL+"/scans/"+scanID, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Auth", apiKey)
		resp, err := client.Do(req)
		if err != nil {
			// Log the error but continue polling if it's a transient network issue
			log.Printf("Error polling scan %s: %v", scanID, err)
			continue
		}

		var result struct {
			CurrentSession struct {
				Status string `json:"status"`
			} `json:"current_session"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close() // Fix: Close body immediately instead of using defer in loop

		if err != nil {
			return fmt.Errorf("failed to decode status for scan %s: %v", scanID, err)
		}

		status := strings.ToLower(result.CurrentSession.Status)
		if status == "completed" {
			return nil // Scan finished successfully
		}
		if status == "failed" || status == "aborted" {
			return fmt.Errorf("scan %s ended with status: %s", scanID, status)
		}

		// If not completed, failed, or aborted, it's still running. Continue polling.
	}
}

// Helper to explicitly fetch all targets and active scans from Acunetix to cross-check duplicates
func fetchExistingTargets(client *http.Client, apiURL, apiKey string) (map[string]bool, int, error) {
	existingMap := make(map[string]bool)
	runningCount := 0
	cursor := "0"

	// 1. Fetch Targets with pagination
	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/targets?c=%s&l=100", apiURL, cursor), nil)
		if err != nil {
			return existingMap, 0, err
		}
		req.Header.Set("X-Auth", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return existingMap, 0, err
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return existingMap, 0, fmt.Errorf("Acunetix targets API returned status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var targetResult struct {
			Targets []struct {
				Address string `json:"address"`
			} `json:"targets"`
			Pagination struct {
				Cursors []interface{} `json:"cursors"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&targetResult); err != nil {
			resp.Body.Close()
			return existingMap, 0, err
		}
		resp.Body.Close()

		for _, t := range targetResult.Targets {
			existingMap[normalizeTarget(t.Address)] = true
		}

		// Check for next cursor (index 0 is next, index 1 might be prev)
		if len(targetResult.Pagination.Cursors) > 0 && targetResult.Pagination.Cursors[0] != nil {
			cursor = fmt.Sprintf("%v", targetResult.Pagination.Cursors[0])
		} else {
			break
		}
	}

	// 2. Fetch Scans to count current running workload with pagination
	cursor = "0"
	for {
		reqS, err := http.NewRequest("GET", fmt.Sprintf("%s/scans?c=%s&l=100", apiURL, cursor), nil)
		if err != nil {
			log.Printf("fetchExistingTargets: Failed to create scan request: %v", err)
			break
		}
		reqS.Header.Set("X-Auth", apiKey)
		respS, err := client.Do(reqS)
		if err != nil {
			log.Printf("fetchExistingTargets: Failed to fetch scans: %v", err)
			break
		}

		if respS.StatusCode != http.StatusOK {
			respS.Body.Close()
			log.Printf("fetchExistingTargets: Scans API returned status %d", respS.StatusCode)
			break
		}

		var scanResult struct {
			Scans []struct {
				CurrentSession struct {
					Status string `json:"status"`
				} `json:"current_session"`
			} `json:"scans"`
			Pagination struct {
				Cursors []interface{} `json:"cursors"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(respS.Body).Decode(&scanResult); err != nil {
			respS.Body.Close()
			log.Printf("fetchExistingTargets: Failed to decode scans: %v", err)
			break
		}
		respS.Body.Close()

		for _, s := range scanResult.Scans {
			stat := strings.ToLower(s.CurrentSession.Status)
			// Scans taking up engine slots:
			if stat == "processing" || stat == "starting" || stat == "queued" || stat == "running" || stat == "scheduled" {
				runningCount++
			}
		}

		if len(scanResult.Pagination.Cursors) > 0 && scanResult.Pagination.Cursors[0] != nil {
			cursor = fmt.Sprintf("%v", scanResult.Pagination.Cursors[0])
		} else {
			break
		}
	}

	log.Printf("fetchExistingTargets: Found %d remote targets, %d active scans", len(existingMap), runningCount)
	return existingMap, runningCount, nil
}

// ----------------------------------------------------
// HTTP HANDLERS
// ----------------------------------------------------

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	return cookie.Value == expectedPasswordHash
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlTemplate)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(req.Password)))
	if hash == expectedPasswordHash {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    hash,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Path:     "/",
		})
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

// Pushes array of targets into the queue
func queueHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload ScanPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	workerCountMu.Lock()
	if payload.MaxScans > 0 {
		maxWorkers = payload.MaxScans
	}
	workerCountMu.Unlock()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second} // longer timeout for fetching master lists

	// Fetch existing targets to prevent remote duplication and sync active count
	existingTargets, remoteRunning, err := fetchExistingTargets(client, payload.APIURL, payload.APIKey)
	if err != nil {
		log.Printf("Warning: Failed to fetch remote targets for deduplication: %v", err)
		// Proceed anyway, but the map will be empty
	}

	log.Printf("Queue Request: Targets=%d, RemoteRunning=%d, MaxLimit=%d", len(payload.Targets), remoteRunning, maxWorkers)

	// Refresh the global load cache immediately when a new batch is submitted
	syncMu.Lock()
	remoteActiveCount = remoteRunning
	lastRemoteSync = time.Now()
	syncMu.Unlock()

	var skipped []string
	var queued int
	localDedupe := make(map[string]bool) // For local deduplication within the current request

	for _, t := range payload.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		norm := normalizeTarget(t)

		// Check for local deduplication within this request
		if localDedupe[norm] {
			skipped = append(skipped, t)
			continue
		}
		localDedupe[norm] = true

		// Check if it already exists remotely
		if existingTargets[norm] {
			skipped = append(skipped, t)
			continue
		}

		// Push to channel
		jobQueue <- ScanJob{
			APIURL: payload.APIURL,
			APIKey: payload.APIKey,
			Target: t,
			Client: &http.Client{Transport: tr, Timeout: 60 * time.Second}, // Increased timeout to handle slow API responses
		}

		resultsStore.Store(t, ScanResult{Target: t, Status: "Pending", Message: "Waiting in queue..."})
		queued++
	}

	w.Header().Set("Content-Type", "application/json")
	syncMu.Lock()
	rac := remoteActiveCount
	syncMu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":         "Jobs processed",
		"queue_length":    len(jobQueue),
		"active_workers":  rac,
		"max_workers":     maxWorkers,
		"skipped_targets": skipped,
		"queued_count":    queued,
	})
}

// Returns state of all submitted targets + Queue stats
func statusHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var results []ScanResult
	resultsStore.Range(func(key, value interface{}) bool {
		results = append(results, value.(ScanResult))
		return true
	})

	syncMu.Lock()
	rac := remoteActiveCount
	syncMu.Unlock()

	workerCountMu.Lock()
	stats := map[string]interface{}{
		"results":        results,
		"queue_length":   len(jobQueue),
		"active_workers": rac,
		"max_workers":    maxWorkers,
	}
	workerCountMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// cancelAllHandler clears all targets with status "Pending" in the ResultsStore
func cancelAllHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	count := 0
	resultsStore.Range(func(key, value interface{}) bool {
		scanRes := value.(ScanResult)
		if scanRes.Status == "Pending" {
			scanRes.Status = "Cancelled"
			scanRes.Message = "Cancelled by user"
			resultsStore.Store(key, scanRes)
			count++
		}
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "cancelled_count": count})
}

// Cancel a pending target by overriding its ResultsStore status
func cancelHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		http.Error(w, "Target required", http.StatusBadRequest)
		return
	}

	if res, ok := resultsStore.Load(req.Target); ok {
		scanRes := res.(ScanResult)
		if scanRes.Status == "Pending" {
			scanRes.Status = "Cancelled"
			scanRes.Message = "Cancelled by user"
			resultsStore.Store(req.Target, scanRes)
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	}

	http.Error(w, "Target not found or already running", http.StatusBadRequest)
}

// Parses JSON Lines, CSV or raw text files and extracts the specified key property
func extractHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := r.ParseMultipartForm(10 << 20) // 10 MB limit
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	extractKey := r.FormValue("extract_key")
	if extractKey == "" {
		http.Error(w, "extract_key is required", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Unable to read file content", http.StatusInternalServerError)
		return
	}

	// Determine file type and extract
	var extracted []string
	filename := strings.ToLower(fileHeader.Filename)
	strContent := string(content)

	if strings.HasSuffix(filename, ".json") {
		// Handle JSON Lines (like FOFA output)
		lines := strings.Split(strContent, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var jsonObj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &jsonObj); err == nil {
				if val, exists := jsonObj[extractKey]; exists && val != nil {
					extracted = append(extracted, fmt.Sprintf("%v", val))
				}
			}
		}
	} else if strings.HasSuffix(filename, ".csv") {
		// Handle CSV
		reader := csv.NewReader(strings.NewReader(strContent))
		records, err := reader.ReadAll()
		if err == nil && len(records) > 0 {
			headerIndex := -1
			for i, header := range records[0] {
				if strings.EqualFold(strings.TrimSpace(header), extractKey) {
					headerIndex = i
					break
				}
			}
			if headerIndex != -1 {
				for rIdx := 1; rIdx < len(records); rIdx++ {
					if len(records[rIdx]) > headerIndex {
						extracted = append(extracted, strings.TrimSpace(records[rIdx][headerIndex]))
					}
				}
			}
		}
	} else {
		// Raw Text fallback, ignore keys just extract non empty lines
		lines := strings.Split(strContent, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				extracted = append(extracted, line)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"extracted_targets": extracted,
		"count":             len(extracted),
	})
}

// Queries Acunetix API directly for global scan statuses
func acunetixStatsHandler(w http.ResponseWriter, r *http.Request) {
	sendJSONError := func(msg string, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}

	if !isAuthenticated(r) {
		sendJSONError("Unauthorized", http.StatusUnauthorized)
		return
	}

	var payload struct {
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendJSONError("Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if payload.APIURL == "" || payload.APIKey == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second} // Increased timeout

	counts := make(map[string]int)
	cursor := "0"
	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/scans?c=%s&l=100", payload.APIURL, cursor), nil)
		if err != nil {
			sendJSONError(err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("X-Auth", payload.APIKey)

		resp, err := client.Do(req)
		if err != nil {
			sendJSONError(err.Error(), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			sendJSONError(fmt.Sprintf("[WebFeeder] Acunetix API error status: %d", resp.StatusCode), http.StatusInternalServerError)
			return
		}

		var result struct {
			Scans []struct {
				CurrentSession struct {
					Status string `json:"status"`
				} `json:"current_session"`
			} `json:"scans"`
			Pagination struct {
				Cursors []interface{} `json:"cursors"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			sendJSONError("[WebFeeder] Failed to parse Acunetix response JSON", http.StatusInternalServerError)
			return
		}
		resp.Body.Close()

		for _, scan := range result.Scans {
			counts[strings.ToLower(scan.CurrentSession.Status)]++
		}

		if len(result.Pagination.Cursors) > 0 && result.Pagination.Cursors[0] != nil {
			cursor = fmt.Sprintf("%v", result.Pagination.Cursors[0])
		} else {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(counts)
}

// ----------------------------------------------------
// UI TEMPLATE (HTML, CSS, JS)
// ----------------------------------------------------
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acunetix SQLi Feeder</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0e14;
            --card-bg: rgba(23, 28, 36, 0.8);
            --border-primary: rgba(255, 255, 255, 0.08);
            --primary: #58a6ff;
            --primary-glow: rgba(88, 166, 255, 0.4);
            --primary-hover: #3182ce;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --danger: #f85149;
            --success: #3fb950;
            --warning: #d29922;
            --input-bg: #0d1117;
            --input-border: #30363d;
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.4);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', system-ui, -apple-system, sans-serif; }
        
        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(88, 166, 255, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(63, 185, 80, 0.03) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 20px;
            overflow-x: hidden;
        }

        .container {
            width: 100%;
            max-width: 850px;
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-primary);
            border-radius: 20px;
            padding: 40px;
            box-shadow: var(--shadow-lg);
            animation: fadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1);
            margin-bottom: 40px;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h1 { font-size: 28px; font-weight: 700; margin-bottom: 10px; text-align: center; color: #fff; letter-spacing: -0.5px; }
        p.subtitle { text-align: center; color: var(--text-muted); margin-bottom: 35px; font-size: 15px; }
        
        .section-header { 
            display: flex; align-items: center; gap: 10px;
            font-size: 16px; font-weight: 600; color: #fff; 
            margin-top: 35px; margin-bottom: 18px;
            position: relative;
        }
        .section-header::after { content: ''; flex: 1; height: 1px; background: var(--input-border); opacity: 0.5; }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 10px;
        }

        .form-group { display: flex; flex-direction: column; gap: 8px; margin-bottom: 5px; }
        .form-group label { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }

        input, textarea, select {
            width: 100%;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            color: var(--text-main);
            padding: 14px 18px;
            border-radius: 10px;
            font-size: 15px;
            outline: none;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }
        
        input:focus, textarea:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-glow), inset 0 2px 4px rgba(0,0,0,0.1);
            background-color: rgba(13, 17, 23, 0.8);
        }

        input[type="file"] { padding: 10px; cursor: pointer; }
        textarea { resize: vertical; min-height: 140px; line-height: 1.6; }

        .btn-primary {
            width: 100%;
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 16px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.2);
            display: flex; justify-content: center; align-items: center; gap: 10px;
            margin-top: 10px;
        }

        .btn-primary:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 6px 16px rgba(88, 166, 255, 0.3); }
        .btn-primary:active { transform: translateY(0); }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--input-border);
            color: #fff;
            padding: 12px 20px;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
        }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.1); border-color: var(--text-muted); }

        /* Global Stats Layout */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat-card {
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border-primary);
            padding: 15px;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .stat-card .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
        .stat-card .value { font-size: 20px; font-weight: 700; color: #fff; }

        .results-container {
            margin-top: 25px;
            background: rgba(0,0,0,0.2);
            border-radius: 15px;
            border: 1px solid var(--input-border);
            overflow: hidden;
        }
        .results-scroll { max-height: 400px; overflow-y: auto; }
        
        .result-item {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            align-items: center;
            gap: 15px;
            padding: 15px 20px;
            border-bottom: 1px solid var(--input-border);
            transition: background 0.2s;
        }
        .result-item:hover { background: rgba(255, 255, 255, 0.02); }
        .result-item:last-child { border-bottom: none; }
        
        .target-url { font-size: 14px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .status-msg { font-size: 12px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .status-pill { font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px; }

        .status-Success { background: rgba(63, 185, 80, 0.1); color: var(--success); }
        .status-Failed { background: rgba(248, 81, 73, 0.1); color: var(--danger); }
        .status-Running { background: rgba(88, 166, 255, 0.1); color: var(--primary); animation: glowPulse 2s infinite ease-in-out; }
        .status-Pending { background: rgba(210, 153, 34, 0.1); color: var(--warning); }
        .status-Cancelled { background: rgba(139, 148, 158, 0.1); color: var(--text-muted); }

        @keyframes glowPulse {
            0% { box-shadow: 0 0 0 0 rgba(88, 166, 255, 0); }
            50% { box-shadow: 0 0 8px 1px rgba(88, 166, 255, 0.3); }
            100% { box-shadow: 0 0 0 0 rgba(88, 166, 255, 0); }
        }

        .loader {
            border: 2px solid rgba(255,255,255,0.2); border-radius: 50%;
            border-top: 2px solid #fff; width: 18px; height: 18px;
            animation: spin 0.8s linear infinite; display: none;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

        /* Mobile Adjustments */
        @media (max-width: 650px) {
            body { padding: 10px; align-items: flex-start; }
            .container { padding: 25px 20px; border-radius: 12px; }
            h1 { font-size: 22px; }
            p.subtitle { margin-bottom: 25px; }
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .result-item { 
                grid-template-columns: 1fr; 
                gap: 8px;
                padding: 20px;
            }
            .target-url { font-size: 15px; white-space: normal; word-break: break-all; }
            .status-msg { font-size: 13px; white-space: normal; }
            .status-actions { display: flex; justify-content: space-between; align-items: center; margin-top: 5px; }

            .form-grid.auth { grid-template-columns: 1fr; }
            .form-grid.extraction { grid-template-columns: 1fr; }
            .form-grid.extraction > .form-group:nth-child(1) { order: 1; }
            .form-grid.extraction > .form-group:nth-child(2) { order: 2; }
            .form-grid.extraction > .form-group:last-child { order: 3; margin-top: 5px; }
        }

        #error-msg { color: var(--danger); text-align: center; margin-top: 15px; font-size: 14px; background: rgba(248, 81, 73, 0.1); padding: 10px; border-radius: 8px; display: none; }
        .hidden { display: none !important; }
    </style>
</head>
<body>

    <!-- LOGIN SCREEN -->
    <div class="container" id="login-screen">
        <h1>Secure Access</h1>
        <p class="subtitle">Authenticate to access the Acunetix UI</p>
        
        <div class="form-group">
            <label>Master Password</label>
            <input type="password" id="password" placeholder="Enter password (MD5 checked)" autocomplete="off" onkeypress="handleLoginKey(event)">
        </div>
        
        <button class="btn-primary" onclick="login()">Enter <span class="loader" id="login-loader"></span></button>
        <div id="error-msg">Incorrect Password!</div>
    </div>

    <!-- MAIN DASHBOARD -->
    <div class="container hidden" id="dashboard-screen">
        <h1>SQLi Target Feeder</h1>
        <p class="subtitle">Queue manager configures up to 10 concurrent Acunetix targets</p>

        <!-- ACUNETIX AUTH -->
        <!-- ACUNETIX AUTH -->
        <div class="form-grid auth">
            <div class="form-group" style="grid-column: span 2;">
                <label>Acunetix API URL</label>
                <input type="text" id="api-url" placeholder="https://your-server:3443/api/v1">
            </div>
            <div class="form-group" style="grid-column: span 2;">
                <label>Acunetix API Key</label>
                <input type="password" id="api-key" placeholder="Enter API Key (X-Auth)">
            </div>
            <div class="form-group">
                <label>Max Scans</label>
                <input type="number" id="max-scans" value="10" min="1" max="100">
            </div>
        </div>

        <!-- GLOBAL STATS -->
        <div class="section-header">🌍 Acunetix Global Status</div>
        <div class="stats-grid" id="global-stats">
            <div class="stat-card">
                <div class="label">Running</div>
                <div class="value status-Running" id="g-processing">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Scheduled</div>
                <div class="value status-Pending" id="g-scheduled">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Queued</div>
                <div class="value status-Pending" id="g-queued">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Completed</div>
                <div class="value status-Success" id="g-completed">0</div>
            </div>
            <div class="stat-card" style="justify-content: center; align-items: center;">
                <button class="btn-secondary" onclick="fetchGlobalStats()" id="btn-gstats" style="width: 100%;">Refresh</button>
            </div>
        </div>

        <!-- FILE EXTRACTOR -->
        <div class="section-header">📂 Bulk File Extraction</div>
        <div class="form-grid extraction">
            <div class="form-group" style="grid-column: span 2;">
                <label>Upload JSONL / CSV / TXT</label>
                <input type="file" id="upload-file" accept=".json,.csv,.txt">
            </div>
            <div class="form-group">
                <label>Extract Key</label>
                <input type="text" id="extract-key" placeholder="e.g. link, host, ip">
            </div>
            <div class="form-group" style="justify-content: flex-end;">
                <button class="btn-secondary" onclick="extractTargets()" id="extract-btn" style="height: 48px;">Extract <span class="loader" id="extract-loader"></span></button>
            </div>
        </div>

        <!-- TARGETS -->
        <div class="section-header">🎯 Scan Queue Setup</div>
        <div class="form-group">
            <label>Targets (One per line). Duplicates will be omitted.</label>
            <textarea id="targets" placeholder="Extracted targets will appear here...&#10;http://target1.com"></textarea>
            <div id="duplicate-warning" style="color: var(--warning); font-size: 13px; margin-top: 8px; display: none;"></div>
        </div>

        <button class="btn-primary" onclick="queueScans()" id="scan-btn">Add to Scan Queue <span class="loader" id="scan-loader"></span></button>
        <button class="btn-secondary" onclick="cancelAllPending()" id="cancel-all-btn" style="margin-top: 10px; color: var(--danger); border-color: rgba(248, 81, 73, 0.2);">Cancel All Pending <span class="loader" id="cancel-all-loader"></span></button>
        
        <!-- SKIPPED TARGETS LOG -->
        <div class="form-group hidden" id="skipped-box" style="margin-top: 20px;">
            <label style="color: var(--warning);">⚠️ Skipped Targets (Already exists in Acunetix remotely)</label>
            <textarea id="skipped-targets" readonly style="min-height: 80px; font-size:12px; color: var(--text-muted); background: #161b22;"></textarea>
        </div>
        
        <!-- QUEUE STATS -->
        <div class="stats-grid hidden" id="queue-stats" style="margin-top: 25px;">
            <div class="stat-card">
                <div class="label">Active Workers</div>
                <div class="value"><span id="stat-active">0</span> / <span id="stat-max">10</span></div>
            </div>
            <div class="stat-card">
                <div class="label">In Queue</div>
                <div class="value" id="stat-queue">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Processed</div>
                <div class="value" id="stat-total">0</div>
            </div>
        </div>

        <!-- RESULTS TABLE -->
        <div class="results-container hidden" id="results-box">
            <div class="results-scroll" id="results-list">
                <!-- Results injected here -->
            </div>
        </div>
    </div>

    <script>
        let pollInterval = null;

        // Auto-load saved credentials
        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('acu_url')) document.getElementById('api-url').value = localStorage.getItem('acu_url');
            if (localStorage.getItem('acu_key')) document.getElementById('api-key').value = localStorage.getItem('acu_key');
            if (localStorage.getItem('acu_max')) document.getElementById('max-scans').value = localStorage.getItem('acu_max');
        });

        if (document.cookie.includes("session_token")) {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('dashboard-screen').classList.remove('hidden');
            startPolling();
        }

        // Normalizes URLs by removing scheme, www., and trailing slashes for duplicate checking
        function normalizeTarget(url) {
            return url.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/$/, '').toLowerCase();
        }

        function handleLoginKey(e) {
            if (e.key === 'Enter') login();
        }

        async function login() {
            const pwd = document.getElementById('password').value;
            const errorMsg = document.getElementById('error-msg');
            const loader = document.getElementById('login-loader');
            
            errorMsg.style.display = 'none';
            loader.style.display = 'inline-block';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pwd })
                });

                if (res.ok) {
                    document.getElementById('login-screen').classList.add('hidden');
                    document.getElementById('dashboard-screen').classList.remove('hidden');
                    document.getElementById('password').value = '';
                    startPolling();
                } else {
                    errorMsg.style.display = 'block';
                }
            } catch (err) {
                errorMsg.innerText = "Network error. Server offline?";
                errorMsg.style.display = 'block';
            } finally {
                loader.style.display = 'none';
            }
        }

        async function extractTargets() {
            const fileInput = document.getElementById('upload-file');
            const extractKey = document.getElementById('extract-key').value.trim();
            const btn = document.getElementById('extract-btn');
            const loader = document.getElementById('extract-loader');

            if (fileInput.files.length === 0) {
                alert("Please select a file to upload.");
                return;
            }
            if (!extractKey && !fileInput.files[0].name.endsWith('.txt')) {
                alert("Please specify an extract key (like 'link' or 'host') for JSON/CSV.");
                return;
            }

            btn.disabled = true;
            loader.style.display = 'inline-block';

            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            formData.append("extract_key", extractKey);

            try {
                const res = await fetch('/api/extract', {
                    method: 'POST',
                    body: formData
                });

                if (res.status === 401) return handleLogout();
                
                const data = await res.json();
                if (data.extracted_targets && data.extracted_targets.length > 0) {
                    const box = document.getElementById('targets');
                    const existing = box.value.trim();
                    const newVal = data.extracted_targets.join('\n');
                    box.value = existing ? existing + '\n' + newVal : newVal;
                    alert("Successfully extracted " + data.count + " targets!");
                } else {
                    alert("No targets could be extracted with the provided key.");
                }
            } catch (err) {
                alert("Error extracting file: " + err);
            } finally {
                btn.disabled = false;
                loader.style.display = 'none';
                fileInput.value = '';
            }
        }

        async function queueScans() {
            const apiUrl = document.getElementById('api-url').value.trim();
            const apiKey = document.getElementById('api-key').value.trim();
            const targetsText = document.getElementById('targets').value.trim();
            const maxScans = parseInt(document.getElementById('max-scans').value) || 10;
            const btn = document.getElementById('scan-btn');
            const loader = document.getElementById('scan-loader');
            const dupWarning = document.getElementById('duplicate-warning');

            if (!apiUrl || !apiKey || !targetsText) {
                alert("Please fill in API URL, API Key, and at least one target.");
                return;
            }

            // Save to localStorage
            localStorage.setItem('acu_url', apiUrl);
            localStorage.setItem('acu_key', apiKey);
            localStorage.setItem('acu_max', maxScans);

            const rawTargets = targetsText.split('\n').map(t => t.trim()).filter(t => t);
            
            // Deduplicate
            const uniqueTargets = [];
            const seen = new Set();
            let dupCount = 0;

            for (const t of rawTargets) {
                const norm = normalizeTarget(t);
                if (!seen.has(norm)) {
                    seen.add(norm);
                    uniqueTargets.push(t);
                } else {
                    dupCount++;
                }
            }

            if (uniqueTargets.length === 0) {
                alert("No valid unique targets found to queue.");
                return;
            }

            if (dupCount > 0) {
                dupWarning.innerText = "Automatically dropped " + dupCount + " duplicate targets (HTTP/HTTPS/www overlaps).";
                dupWarning.style.display = 'block';
            } else {
                dupWarning.style.display = 'none';
            }

            btn.disabled = true;
            loader.style.display = 'inline-block';

            try {
                const res = await fetch('/api/scan/queue', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        api_url: apiUrl,
                        api_key: apiKey,
                        targets: uniqueTargets,
                        max_scans: maxScans
                    })
                });

                const data = await res.json();
                
                if (data.skipped_targets && data.skipped_targets.length > 0) {
                    const skippedBox = document.getElementById('skipped-box');
                    const skippedTextarea = document.getElementById('skipped-targets');
                    skippedBox.classList.remove('hidden');
                    
                    const newSkips = data.skipped_targets.join('\n');
                    const existingSkips = skippedTextarea.value.trim();
                    skippedTextarea.value = existingSkips ? existingSkips + '\n' + newSkips : newSkips;
                    
                    if (dupCount > 0) {
                        dupWarning.innerText = "Dropped " + dupCount + " local duplicates. Dropped " + data.skipped_targets.length + " remote Acunetix duplicates.";
                    } else {
                        dupWarning.innerText = "Dropped " + data.skipped_targets.length + " remote Acunetix duplicates.";
                        dupWarning.style.display = 'block';
                    }
                }

                document.getElementById('targets').value = '';
                // Immediately poll to show pending items
                pollStatus();

            } catch (err) {
                alert("An error occurred communicating with the server.");
            } finally {
                btn.disabled = false;
                loader.style.display = 'none';
            }
        }

        let lastGlobalFetch = 0;

        function startPolling() {
            if (!pollInterval) {
                pollStatus(); // Initial call
                pollInterval = setInterval(pollStatus, 2500); // Check every 2.5s
            }
        }

        async function fetchGlobalStats() {
            const apiUrl = document.getElementById('api-url').value.trim();
            const apiKey = document.getElementById('api-key').value.trim();
            if (!apiUrl || !apiKey) return;
            
            // Auto Update Storage if firing
            localStorage.setItem('acu_url', apiUrl);
            localStorage.setItem('acu_key', apiKey);
            
            const btn = document.getElementById('btn-gstats');
            btn.innerText = "Loading...";
            
            try {
                const res = await fetch('/api/acunetix/stats', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_url: apiUrl, api_key: apiKey })
                });
                if (res.status === 401) return handleLogout();
                
                const data = await res.json();
                document.getElementById('g-processing').innerText = data.processing || 0;
                document.getElementById('g-scheduled').innerText = data.scheduled || 0;
                document.getElementById('g-queued').innerText = data.queued || 0;
                document.getElementById('g-completed').innerText = data.completed || 0;
                lastGlobalFetch = Date.now();
            } catch (err) {
                console.error("Stats Error:", err);
            } finally {
                btn.innerText = "Refresh";
            }
        }

        async function pollStatus() {
            try {
                const res = await fetch('/api/scan/status');
                if (res.status === 401) return handleLogout();
                
                const data = await res.json();
                
                // Update Stats
                document.getElementById('queue-stats').classList.remove('hidden');
                document.getElementById('stat-active').innerText = data.active_workers;
                document.getElementById('stat-max').innerText = data.max_workers;
                document.getElementById('stat-queue').innerText = data.queue_length;
                document.getElementById('stat-total').innerText = (data.results || []).length;

                // Refresh Acunetix Global Stats every 15s to avoid heavy strain
                if (Date.now() - lastGlobalFetch > 15000) {
                    fetchGlobalStats();
                }

                // Build Table
                const resultsBox = document.getElementById('results-box');
                const resultsList = document.getElementById('results-list');
                if (data.results && data.results.length > 0) {
                    resultsBox.classList.remove('hidden');
                    let html = '';
                    
                    const sorted = data.results.sort((a,b) => {
                        const score = {"Running":3, "Pending":2, "Failed":1, "Success":0, "Cancelled": -1};
                        return score[b.status] - score[a.status];
                    });

                    sorted.forEach(item => {
                        let cancelHtml = "";
                        if (item.status === 'Pending') {
                            cancelHtml = '<button onclick="cancelTarget(\'' + item.target + '\')" class="btn-secondary" style="padding: 4px 10px; font-size:11px; color:var(--danger); border-color:rgba(248, 81, 73, 0.2);">Cancel</button>';
                        }
                        
                        html += '<div class="result-item">' +
                                '<div class="target-url" title="' + item.target + '">' + item.target + '</div>' +
                                '<div class="status-msg" title="' + item.message + '">' + item.message + '</div>' +
                                '<div class="status-actions">' +
                                    '<span class="status-pill status-' + item.status + '">' + item.status + '</span>' +
                                    cancelHtml +
                                '</div>' +
                            '</div>';
                    });
                    resultsList.innerHTML = html;
                }
            } catch (err) {
                console.error("Polling error", err);
            }
        }

        async function cancelTarget(target) {
            try {
                const res = await fetch('/api/scan/cancel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target })
                });
                if (res.ok) {
                    pollStatus(); // force UI update
                } else {
                    alert("Could not cancel. It may have already started.");
                }
            } catch (err) {
                console.error("Cancel Error: ", err);
            }
        }

        async function cancelAllPending() {
            if (!confirm("Are you sure you want to cancel ALL pending targets in the local queue?")) return;
            
            const btn = document.getElementById('cancel-all-btn');
            const loader = document.getElementById('cancel-all-loader');
            btn.disabled = true;
            loader.style.display = 'inline-block';

            try {
                const res = await fetch('/api/scan/cancel-all', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                if (res.ok) {
                    const data = await res.json();
                    alert("Cancelled " + data.cancelled_count + " pending targets.");
                    pollStatus(); // force UI update
                } else {
                    alert("Failed to cancel pending targets.");
                }
            } catch (err) {
                console.error("Cancel All Error: ", err);
            } finally {
                btn.disabled = false;
                loader.style.display = 'none';
            }
        }

        function handleLogout() {
            document.cookie = "session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            window.location.reload();
        }
    </script>
</body>
</html>`
