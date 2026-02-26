# Obtaining Acunetix API Keys on Ubuntu 20.04

Acunetix enforces secure retrieval of its API keys via its web management interface. There is no direct, officially supported command-line tool to extract plain-text API keys from server configuration files, as this would violate security best practices and expose secrets in the event of a compromised host.

To securely get your API key from a running Acunetix server, you will need to access its visual web UI. If the Acunetix instance is only accessible locally on your Ubuntu server (e.g., bound to `localhost` or placed behind a firewall for protection), the standard procedure is to use an SSH port forward to securely access the interface from your current machine.

## Step 1: Securely Access the Web UI via SSH Tunnel

By default, Acunetix typically listens on port `3443` for its web-based management console. You can establish an encrypted tunnel to interact with it directly from your web browser. 

Run the following SSH command on your local machine:

```bash
ssh -L 3443:localhost:3443 your_username@<ubuntu-server-ip>
```

*(This forwards your local `localhost:3443` to the remote server's `localhost:3443` over an encrypted SSH connection)*

## Step 2: Retrieve the API Key from the Profile Dashboard

1. Open your web browser and navigate to `https://localhost:3443` (You may need to bypass the self-signed certificate warning).
2. Log in using your Acunetix administrator credentials.
3. Once logged in to the dashboard, click on your **Profile Name** (located in the top-right corner of the interface) and select **Profile** or **API Settings** from the dropdown menu.
4. Scroll down to the **API Key** section.
5. If no key is present, click **Generate new API key**. 
6. Click **Copy** to save the API key to your clipboard.

## Step 3: Run the Automation CLI Securely

Now that you have accessed the API key securely, you can use the Go application. Because API credentials should not be passed to standard output or as command-line arguments (which might leak to the Linux `history` command or `ps aux` command for other users on the system), our script consumes `ENV` variables entirely.

Run our tool like so:

```bash
# Set your environment variables (Prefix commands with a space in bash to ensure they're potentially kept out of history depending on configuration)
 export ACUNETIX_API_URL="https://localhost:3443/api/v1"
 export ACUNETIX_API_KEY="your-retrieved-api-key"
 export TARGET_URL="http://victim-target.test"

# Run the compiled tool
./feed_acu
```

*(Note: The Acunetix preset profile ID for "SQL Injection Vulnerabilities" is typically `11111111-1111-1111-1111-111111111113`. The tool defaults to this automatically. You can always override this by passing `export PROFILE_ID="..."`)*
