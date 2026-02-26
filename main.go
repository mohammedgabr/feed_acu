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

// Global Job Manager
var jobQueue = make(chan ScanJob, 10000)
var resultsStore = sync.Map{} // thread-safe map to store: targetURL -> ScanResult
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
	// Start Worker Pool
	for i := 0; i < maxWorkers; i++ {
		go worker()
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/scan/queue", queueHandler)
	http.HandleFunc("/api/scan/status", statusHandler)
	http.HandleFunc("/api/extract", extractHandler)
	http.HandleFunc("/api/acunetix/stats", acunetixStatsHandler)

	port := "8080"
	fmt.Printf("[+] Starting Acunetix Web Feeder with Worker Queue on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

// ----------------------------------------------------
// WORKER POOL
// ----------------------------------------------------
func worker() {
	for job := range jobQueue {
		// Mark as running
		resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Running", Message: "Starting scan..."})

		activeMu.Lock()
		activeWorkers++
		activeMu.Unlock()

		// 1. Add Target
		targetID, err := addTarget(job.Client, job.APIURL, job.APIKey, job.Target)
		if err != nil {
			resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: fmt.Sprintf("Add Target Error: %v", err)})
			activeMu.Lock()
			activeWorkers--
			activeMu.Unlock()
			continue
		}

		// 2. Start Scan
		scanID, err := startScan(job.Client, job.APIURL, job.APIKey, targetID)
		if err != nil {
			resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: fmt.Sprintf("Start Scan Error: %v", err)})
		} else {
			resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Running", Message: "Scan running in Acunetix..."})
			// 3. Poll Scan Status
			err = pollScan(job.Client, job.APIURL, job.APIKey, scanID)
			if err != nil {
				resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Failed", Message: err.Error()})
			} else {
				resultsStore.Store(job.Target, ScanResult{Target: job.Target, Status: "Success", Message: "Scan completed"})
			}
		}

		activeMu.Lock()
		activeWorkers--
		activeMu.Unlock()
	}
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
			continue
		}

		var statusResp struct {
			CurrentSession struct {
				Status string `json:"status"`
			} `json:"current_session"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&statusResp); err == nil {
			status := statusResp.CurrentSession.Status
			resp.Body.Close()
			if status == "completed" || status == "aborted" || status == "failed" {
				if status == "aborted" || status == "failed" {
					return fmt.Errorf("Scan finished with status: %s", status)
				}
				return nil
			}
		} else {
			resp.Body.Close()
		}
	}
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
	if payload.MaxScans > 0 && payload.MaxScans > maxWorkers {
		diff := payload.MaxScans - maxWorkers
		for i := 0; i < diff; i++ {
			go worker()
		}
		maxWorkers = payload.MaxScans
	}
	workerCountMu.Unlock()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	for _, t := range payload.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		resultsStore.Store(t, ScanResult{Target: t, Status: "Pending", Message: "Waiting in queue..."})
		jobQueue <- ScanJob{
			APIURL: payload.APIURL,
			APIKey: payload.APIKey,
			Target: t,
			Client: client,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Jobs added to queue"})
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

	activeMu.Lock()
	workerCountMu.Lock()
	stats := map[string]interface{}{
		"results":        results,
		"queue_length":   len(jobQueue),
		"active_workers": activeWorkers,
		"max_workers":    maxWorkers,
	}
	workerCountMu.Unlock()
	activeMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var payload struct {
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.APIURL == "" || payload.APIKey == "" {
		json.NewEncoder(w).Encode(map[string]int{})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", payload.APIURL+"/scans?c=0&l=1000", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Auth", payload.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Acunetix returned status %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}

	var result struct {
		Scans []struct {
			CurrentSession struct {
				Status string `json:"status"`
			} `json:"current_session"`
		} `json:"scans"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Failed to parse Acunetix response", http.StatusInternalServerError)
		return
	}

	counts := make(map[string]int)
	for _, scan := range result.Scans {
		counts[scan.CurrentSession.Status]++
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
            --bg-color: #0d1117;
            --glass-bg: rgba(22, 27, 34, 0.7);
            --glass-border: rgba(255, 255, 255, 0.1);
            --primary: #58a6ff;
            --primary-hover: #3182ce;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --danger: #f85149;
            --success: #3fb950;
            --warning: #d29922;
            --input-bg: #0d1117;
            --input-border: #30363d;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', sans-serif; }
        
        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 15% 50%, rgba(88, 166, 255, 0.08), transparent 25%),
                              radial-gradient(circle at 85% 30%, rgba(63, 185, 80, 0.05), transparent 25%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .container {
            width: 100%;
            max-width: 700px;
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            transition: all 0.3s ease;
        }

        h1 { font-size: 24px; font-weight: 600; margin-bottom: 8px; text-align: center; color: #fff; }
        p.subtitle { text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }
        
        .section-title { font-size: 16px; color: #fff; border-bottom: 1px solid var(--input-border); padding-bottom: 5px; margin-bottom: 15px; margin-top: 30px;}

        .form-group { margin-bottom: 20px; }
        .form-row { display: flex; gap: 15px; }
        .form-row .form-group { flex: 1; }

        .form-group label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 500; }

        input, textarea, select {
            width: 100%;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            color: var(--text-main);
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        
        input:focus, textarea:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2);
        }

        input[type="file"] { padding: 9px; cursor: pointer; }

        textarea { resize: vertical; min-height: 120px; line-height: 1.5; }

        button {
            width: 100%;
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 14px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
        }

        button:hover { background: var(--primary-hover); }
        button:active { transform: scale(0.98); }
        button:disabled { background: var(--text-muted); cursor: not-allowed; transform: none; }
        
        button.secondary { background: #21262d; border: 1px solid var(--input-border); }
        button.secondary:hover { background: #30363d; }

        #error-msg { color: var(--danger); text-align: center; margin-top: 15px; font-size: 14px; display: none; }
        .hidden { display: none !important; }

        .queue-stats {
            display: flex;
            justify-content: space-between;
            background: #21262d;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 13px;
            margin-top: 20px;
            border: 1px solid var(--input-border);
        }
        .queue-stats span { font-weight: 600; color: #fff;}

        /* Results table */
        .results {
            margin-top: 15px;
            border: 1px solid var(--input-border);
            border-radius: 8px;
            overflow: hidden;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .result-item {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 16px; border-bottom: 1px solid var(--input-border);
            font-size: 13px;
            background: rgba(0,0,0,0.2);
        }
        .result-item:last-child { border-bottom: none; }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .status-Success { color: var(--success); font-weight: 600; }
        .status-Failed { color: var(--danger); font-weight: 600; }
        .status-Running { color: var(--primary); font-weight: 600; animation: pulse 1.5s infinite;}
        .status-Pending { color: var(--warning); font-weight: 600; }
        
        .loader {
            border: 3px solid rgba(255,255,255,0.3); border-radius: 50%;
            border-top: 3px solid #fff; width: 20px; height: 20px;
            animation: spin 1s linear infinite; display: inline-block;
            vertical-align: middle; margin-left: 10px; display: none;
        }

        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
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
        
        <button onclick="login()">Enter <span class="loader" id="login-loader"></span></button>
        <div id="error-msg">Incorrect Password!</div>
    </div>

    <!-- MAIN DASHBOARD -->
    <div class="container hidden" id="dashboard-screen">
        <h1>SQLi Target Feeder</h1>
        <p class="subtitle">Queue manager configures up to 10 concurrent Acunetix targets</p>

        <!-- ACUNETIX AUTH -->
        <div class="form-row">
            <div class="form-group" style="flex: 2;">
                <label>Acunetix API URL</label>
                <input type="text" id="api-url" placeholder="https://your-server:3443/api/v1">
            </div>
            <div class="form-group" style="flex: 2;">
                <label>Acunetix API Key</label>
                <input type="password" id="api-key" placeholder="Enter API Key (X-Auth)">
            </div>
            <div class="form-group" style="flex: 1;">
                <label>Max Scans</label>
                <input type="number" id="max-scans" value="10" min="1" max="100">
            </div>
        </div>

        <!-- GLOBAL STATS -->
        <div class="section-title">🌍 Acunetix Global Status</div>
        <div class="queue-stats" id="global-stats" style="margin-top: 5px; margin-bottom: 20px;">
            <div>Processing/Running: <span id="g-processing" class="status-Running">0</span></div>
            <div>Scheduled: <span id="g-scheduled" class="status-Pending">0</span></div>
            <div>Queued: <span id="g-queued" class="status-Pending">0</span></div>
            <div>Completed: <span id="g-completed" class="status-Success">0</span></div>
            <div><button style="padding: 4px 12px; font-size: 11px; width: auto;" class="secondary" onclick="fetchGlobalStats()" id="btn-gstats">Refresh</button></div>
        </div>

        <!-- FILE EXTRACTOR -->
        <div class="section-title">📂 Bulk File Extraction</div>
        <div class="form-row" style="align-items: flex-end;">
            <div class="form-group" style="flex: 2;">
                <label>Upload JSONL / CSV / TXT</label>
                <input type="file" id="upload-file" accept=".json,.csv,.txt">
            </div>
            <div class="form-group" style="flex: 1;">
                <label>Extract Key</label>
                <input type="text" id="extract-key" placeholder="e.g. link, host, ip">
            </div>
            <div class="form-group" style="flex: 1;">
                <button class="secondary" onclick="extractTargets()" id="extract-btn">Extract <span class="loader" id="extract-loader"></span></button>
            </div>
        </div>

        <!-- TARGETS -->
        <div class="section-title">🎯 Scan Queue Setup</div>
        <div class="form-group">
            <label>Targets (One per line)</label>
            <textarea id="targets" placeholder="Extracted targets will appear here...&#10;http://target1.com"></textarea>
        </div>

        <button onclick="queueScans()" id="scan-btn">Add to Scan Queue <span class="loader" id="scan-loader"></span></button>
        
        <!-- QUEUE STATS -->
        <div class="queue-stats hidden" id="queue-stats">
            <div>Active Workers: <span id="stat-active">0</span>/<span id="stat-max">10</span></div>
            <div>Waiting in Queue: <span id="stat-queue">0</span></div>
            <div>Total Processed: <span id="stat-total">0</span></div>
        </div>

        <!-- RESULTS TABLE -->
        <div class="results hidden" id="results-box">
            <!-- Results injected here -->
        </div>
    </div>

    <script>
        let pollInterval = null;

        if (document.cookie.includes("session_token")) {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('dashboard-screen').classList.remove('hidden');
            startPolling();
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

            if (!apiUrl || !apiKey || !targetsText) {
                alert("Please fill in API URL, API Key, and at least one target.");
                return;
            }

            const targets = targetsText.split('\n').map(t => t.trim()).filter(t => t);

            btn.disabled = true;
            loader.style.display = 'inline-block';

            try {
                const res = await fetch('/api/scan/queue', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        api_url: apiUrl,
                        api_key: apiKey,
                        targets: targets,
                        max_scans: maxScans
                    })
                });

                if (res.status === 401) return handleLogout();
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
                if (data.results && data.results.length > 0) {
                    resultsBox.classList.remove('hidden');
                    let html = '';
                    
                    // Sort so Running is at top, then pending, then finished
                    const sorted = data.results.sort((a,b) => {
                        const score = {"Running":3, "Pending":2, "Failed":1, "Success":0};
                        return score[b.status] - score[a.status];
                    });

                    sorted.forEach(item => {
                        html += "<div class=\"result-item\"><span style=\"max-width: 50%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\" title=\"" + item.target + "\">" + item.target + "</span><span style=\"font-size:11px; color:#8b949e; max-width: 30%; overflow: hidden; white-space: nowrap;\" title=\"" + item.message + "\">" + item.message + "</span><span class=\"status-" + item.status + "\">[" + item.status + "]</span></div>";
                    });
                    resultsBox.innerHTML = html;
                }
            } catch (err) {
                console.error("Polling error", err);
            }
        }

        function handleLogout() {
            document.cookie = "session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            window.location.reload();
        }
    </script>
</body>
</html>`
