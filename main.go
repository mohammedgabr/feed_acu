package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	// Store the expected MD5 hash for the password "Zalabia@9"
	expectedPasswordHash = fmt.Sprintf("%x", md5.Sum([]byte("Zalabia@9")))
	// Profile ID for SQL Injection Vulnerabilities
	sqlInjectionProfileID = "11111111-1111-1111-1111-111111111113"
)

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

// Structs for API interaction
type ScanPayload struct {
	APIURL  string   `json:"api_url"`
	APIKey  string   `json:"api_key"`
	Targets []string `json:"targets"`
}

type ScanResult struct {
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/scan", scanHandler)

	port := "8080"
	fmt.Printf("[+] Starting Acunetix Web Feeder on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

// Validates the session cookie
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	// A simple check: if the cookie value matches our static hash, they are authenticated.
	// In a real production app, use proper randomized session tokens and a session store.
	return cookie.Value == expectedPasswordHash
}

// Serves the HTML UI
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlTemplate)
}

// Handles the login request
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Hash the incoming password with MD5
	hash := fmt.Sprintf("%x", md5.Sum([]byte(req.Password)))

	if hash == expectedPasswordHash {
		// Set a secure cookie for the session
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

// Handles the scan request payload
func scanHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Disable local certificate verification since Acunetix often uses self-signed TLS certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var results []ScanResult

	for _, targetURL := range payload.Targets {
		targetURL = strings.TrimSpace(targetURL)
		if targetURL == "" {
			continue
		}

		// 1. Add Target
		targetID, err := addTarget(client, payload.APIURL, payload.APIKey, targetURL)
		if err != nil {
			results = append(results, ScanResult{Target: targetURL, Success: false, Message: fmt.Sprintf("Failed to add: %v", err)})
			continue
		}

		// 2. Start Scan
		err = startScan(client, payload.APIURL, payload.APIKey, targetID)
		if err != nil {
			results = append(results, ScanResult{Target: targetURL, Success: false, Message: fmt.Sprintf("Failed to scan: %v", err)})
			continue
		}

		results = append(results, ScanResult{Target: targetURL, Success: true, Message: "Scan started successfully"})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func addTarget(client *http.Client, apiURL, apiKey, targetURL string) (string, error) {
	reqData := TargetRequest{
		Address:     targetURL,
		Description: "Added via Web Feeder",
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

func startScan(client *http.Client, apiURL, apiKey, targetID string) error {
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
		return err
	}

	req.Header.Set("X-Auth", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Status %s: %s", resp.Status, string(bodyBytes))
	}

	return nil
}

// ----------------------------------------------------
// UI TEMPLATE (HTML, CSS, JS)
// A premium dark theme using glassmorphism aesthetics.
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
            max-width: 600px;
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            transition: all 0.3s ease;
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            text-align: center;
            color: #fff;
        }

        p.subtitle {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 30px;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
        }

        input, textarea {
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

        input:focus, textarea:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
            line-height: 1.5;
        }

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

        button:hover {
            background: var(--primary-hover);
        }

        button:active {
            transform: scale(0.98);
        }

        button:disabled {
            background: var(--text-muted);
            cursor: not-allowed;
            transform: none;
        }

        #error-msg {
            color: var(--danger);
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
        }

        .hidden { display: none !important; }

        /* Results table */
        .results {
            margin-top: 30px;
            border: 1px solid var(--input-border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .result-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            border-bottom: 1px solid var(--input-border);
            font-size: 13px;
        }

        .result-item:last-child {
            border-bottom: none;
        }

        .status-success { color: var(--success); font-weight: 600; }
        .status-error { color: var(--danger); font-weight: 600; }
        
        /* Spinner */
        .loader {
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top: 3px solid #fff;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            vertical-align: middle;
            margin-left: 10px;
            display: none;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
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
        <p class="subtitle">Bulk start targeted SQL Injection scans</p>

        <div class="form-group">
            <label>Acunetix API URL</label>
            <input type="text" id="api-url" placeholder="https://your-server:3443/api/v1">
        </div>

        <div class="form-group">
            <label>Acunetix API Key</label>
            <input type="password" id="api-key" placeholder="Enter API Key (X-Auth)">
        </div>

        <div class="form-group">
            <label>Targets (One per line)</label>
            <textarea id="targets" placeholder="http://target1.com&#10;http://target2.com/param=test"></textarea>
        </div>

        <button onclick="startScans()" id="scan-btn">Deploy Scans <span class="loader" id="scan-loader"></span></button>
        
        <div class="results hidden" id="results-box">
            <!-- Results injected here -->
        </div>
    </div>

    <script>
        // Use a simple mechanism to check if cookie exists to display standard UI on reload
        if (document.cookie.includes("session_token")) {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('dashboard-screen').classList.remove('hidden');
        }

        function handleLoginKey(e) {
            if (e.key === 'Enter') {
                login();
            }
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

        async function startScans() {
            const apiUrl = document.getElementById('api-url').value.trim();
            const apiKey = document.getElementById('api-key').value.trim();
            const targetsText = document.getElementById('targets').value.trim();
            const btn = document.getElementById('scan-btn');
            const loader = document.getElementById('scan-loader');
            const resultsBox = document.getElementById('results-box');

            if (!apiUrl || !apiKey || !targetsText) {
                alert("Please fill in API URL, API Key, and at least one target.");
                return;
            }

            const targets = targetsText.split('\n').map(t => t.trim()).filter(t => t);

            btn.disabled = true;
            loader.style.display = 'inline-block';
            resultsBox.innerHTML = '';
            resultsBox.classList.add('hidden');

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        api_url: apiUrl,
                        api_key: apiKey,
                        targets: targets
                    })
                });

                if (res.status === 401) {
                    document.cookie = "session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                    window.location.reload();
                    return;
                }

                const data = await res.json();
                
                resultsBox.innerHTML = '';
                data.forEach(item => {
                    const statusClass = item.success ? 'status-success' : 'status-error';
                    const statusText = item.success ? '✓ Scan Started' : '✗ Failed: ' + item.message;
                    
                        resultsBox.innerHTML += "<div class=\"result-item\"><span style=\"max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\" title=\"" + item.target + "\">" + item.target + "</span><span class=\"" + statusClass + "\">" + statusText + "</span></div>";
                });
                
                resultsBox.classList.remove('hidden');

            } catch (err) {
                alert("An error occurred communicating with the server.");
            } finally {
                btn.disabled = false;
                loader.style.display = 'none';
            }
        }
    </script>
</body>
</html>`
