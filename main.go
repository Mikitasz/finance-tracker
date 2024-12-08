package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// OAuth configuration
var oauth2Config = oauth2.Config{
	ClientID:     "", // Replace with your GitHub Client ID
	ClientSecret: "", // Replace with your GitHub Client Secret
	RedirectURL:  "http://localhost:8080/callback",
	Scopes:       []string{"repo", "user"},
	Endpoint:     github.Endpoint,
}

var oauth2StateString = "randomstate"

// Store user tokens
var userTokens = make(map[string]*oauth2.Token)

// GitHub repository details
const (
	githubUsername = "Mikitasz" // Replace with your GitHub username
	repoName       = "finance"  // Replace with your private repository name
	branchName     = "main"     // The branch where commits will be made
)

func main() {
	// Handle static files (CSS, images, etc.)
	fs := http.FileServer(http.Dir("public"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/finance", handleFinance)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/add-cost", handleAddCost)

	log.Println("Starting server on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// Handle the main login page
func handleMain(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/login.html")
}

// Handle login, redirect to GitHub for OAuth authentication
func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL(oauth2StateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

// Handle the callback from GitHub after user login
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauth2StateString {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	client := oauth2Config.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode user info: %v", err), http.StatusInternalServerError)
		return
	}

	username := user["login"].(string)
	userTokens[username] = token

	// Set a cookie to keep track of the logged-in user
	http.SetCookie(w, &http.Cookie{
		Name:    "username",
		Value:   username,
		Expires: time.Now().Add(24 * time.Hour),
	})

	http.Redirect(w, r, "/finance", http.StatusFound)
}

// Handle the finance page
func handleFinance(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		http.Error(w, "You must be logged in to access this page", http.StatusForbidden)
		return
	}
	filePath := getFileForUser(username)

	// Retrieve commit history
	commitMessages, err := getCommitMessages(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting commit messages: %v", err), http.StatusInternalServerError)
		return
	}
	tmpl := `<html>
	<head>
		<title>Finance Tracker</title>
		<link rel="stylesheet" href="/static/styles/style.css">
	</head>
	<body>
		<div style="display: flex; justify-content: space-between; align-items: center;">
			<h1>Finance Tracker</h1>
			<div>
				<img src="https://github.com/{{.Username}}.png" width="50" height="50" style="border-radius: 50%;">
				<span>{{.Username}}</span>
				<a href="/logout">Logout</a>
			</div>
		</div>
		<form method="POST" action="/add-cost">
			<label>Commit Message: <input type="text" name="commitMessage" required></label><br>
			<label>Cost: <input type="number" name="cost" required></label><br>
			<button type="submit">Add Cost</button>
		</form>
		<h2>Commit History</h2>
		<div style="max-height: 300px; overflow-y: scroll;">
			<ul>
				{{range .CommitMessages}}
					<li><strong>{{.User}}:</strong> ({{.Time}}): {{.Message}}</li>
				{{end}}
			</ul>
		</div>
	</body>
	</html>`

	data := struct {
		Username       string
		CommitMessages []CommitMessage
	}{
		Username:       username,
		CommitMessages: commitMessages,
	}

	tmplExecute(w, tmpl, data)
}

// Retrieve commit messages from GitHub file
func getCommitMessages(filePath string) ([]CommitMessage, error) {
	var commitMessages []CommitMessage

	token := userTokens["Mikitasz"] // Example, could be dynamic per user
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s", githubUsername, repoName, filePath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var commits []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	for _, commit := range commits {
		commitMessage := commit["commit"].(map[string]interface{})["message"].(string)
		author := commit["commit"].(map[string]interface{})["author"].(map[string]interface{})["name"].(string)
		commitTime := commit["commit"].(map[string]interface{})["author"].(map[string]interface{})["date"].(string)
		parsedTime, err := time.Parse(time.RFC3339, commitTime) // Parse the time
		if err != nil {
			return nil, err
		}
		commitMessages = append(commitMessages, CommitMessage{User: author, Message: commitMessage, Time: getPolishTime(parsedTime)})
	}

	return commitMessages, nil
}
func getPolishTime(t time.Time) string {
	// Load the Europe/Warsaw time zone
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		log.Printf("Failed to load time zone: %v", err)
		return t.Format("02.01.2006-15:04") // Fallback to default UTC if error occurs
	}

	// Convert the time to the Warsaw time zone
	warSawTime := t.In(loc)

	// Format the time in the Polish style (DD.MM.YYYY-HH:MM)
	return warSawTime.Format("02.01.2006-15:04")
}

type CommitMessage struct {
	User    string
	Message string
	Time    string
}

// Handle adding a cost and committing to GitHub
func handleAddCost(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		http.Error(w, "You must be logged in to commit", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	commitMessage := r.FormValue("commitMessage")
	cost := r.FormValue("cost")

	content := fmt.Sprintf("User: %s\nCost: %s\nMessage: %s\n\n", username, cost, commitMessage)

	if err := commitToGitHub(username, commitMessage, content); err != nil {
		http.Error(w, fmt.Sprintf("Failed to commit: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/finance", http.StatusFound)
}

// Function to get user-specific file path
func getFileForUser(username string) string {
	if username == "Mikitasz" {
		return "Mikita.txt"
	}
	return "Ania.txt"
}

// Commit to GitHub
func commitToGitHub(username, message, content string) error {
	filePath := getFileForUser(username)
	token, exists := userTokens[username]
	if !exists {
		return fmt.Errorf("user not logged in or token missing")
	}

	// GitHub API URL to get the file content (also includes the sha)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", githubUsername, repoName, filePath)

	// Fetch the file information to get the sha
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the file exists
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("file not found")
	}

	// Decode the response body to get the sha and content
	var fileData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fileData); err != nil {
		return err
	}

	// Get the sha of the file
	sha := fileData["sha"].(string)

	// Now prepare the commit request
	updateRequest := map[string]interface{}{
		"message": message,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"sha":     sha,
		"branch":  branchName,
	}

	bodyBytes, err := json.Marshal(updateRequest)
	if err != nil {
		return err
	}

	// Create a new PUT request to update the file
	req, err = http.NewRequest("PUT", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to commit to GitHub: %s", string(body))
	}

	return nil
}

// Handle logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "username",
		Value:  "",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// Helper function to get the logged-in user
func getLoggedInUser(r *http.Request) string {
	cookie, err := r.Cookie("username")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// Render a template
func tmplExecute(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.New("main").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
