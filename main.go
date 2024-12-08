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
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Список разрешенных IP-адресов
var allowedIPs = map[string]bool{
	"46.205.202.217": true, // Пример разрешенного IP
	// Добавьте сюда другие разрешенные IP-адреса
}

func isAllowedIP(r *http.Request) bool {
	// Получаем IP-адрес клиента
	ip := r.RemoteAddr

	// Если сервер за прокси, используем заголовок X-Forwarded-For
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Преобразуем список адресов в строку и берем первый (например, первый IP в списке)
		ip = strings.Split(forwardedFor, ",")[0]
	}

	// Проверяем, разрешен ли этот IP
	return allowedIPs[ip]
}

// OAuth configuration
var oauth2Config = oauth2.Config{
	ClientID:     "Ov23li8AWGo3ViCNChVm",                     // Replace with your GitHub Client ID
	ClientSecret: "6f114c21e8faa5e05ab54976b95f0fa50dbe3d92", // Replace with your GitHub Client Secret
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
	if !isAllowedIP(r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	http.ServeFile(w, r, "public/index.html")
}

// Handle login, redirect to GitHub for OAuth authentication
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !isAllowedIP(r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	url := oauth2Config.AuthCodeURL(oauth2StateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

// Handle the callback from GitHub after user login
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if !isAllowedIP(r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
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
	if !isAllowedIP(r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	username := getLoggedInUser(r)
	if username == "" {
		http.Error(w, "You must be logged in to access this page", http.StatusForbidden)
		return
	}
	//filePath := getFileForUser(username)

	mikitaCommitMessages, err := getCommitMessages("Mikita.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting Mikita commit messages: %v", err), http.StatusInternalServerError)
		return
	}

	aniaCommitMessages, err := getCommitMessages("Ania.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting Ania commit messages: %v", err), http.StatusInternalServerError)
		return
	}
	allCommitMessages := append(mikitaCommitMessages, aniaCommitMessages...)
	sort.Slice(allCommitMessages, func(i, j int) bool {
		return allCommitMessages[i].Time > allCommitMessages[j].Time
	})
	// Calculate the difference between Mikita's and Ania's current costs
	mikitaSum, _ := getCurrentSum("Mikita.txt")
	aniaSum, _ := getCurrentSum("Ania.txt")

	// Retrieve commit history
	//commitMessages, err := getCommitMessages(filePath)
	//if err != nil {
	//	http.Error(w, fmt.Sprintf("Error getting commit messages: %v", err), http.StatusInternalServerError)
	//	return
	//}
	tmpl := `<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Finance Tracker</title>
    <link rel="stylesheet" href="/static/styles/style.css">
</head>
<body>
    <header class="header">
        <div class="profile-info">
            <img src="https://github.com/{{.Username}}.png" alt="GitHub Avatar" class="avatar">
            <span>{{.Username}}</span>
        </div>
        <a href="/logout" class="logout-btn">Logout</a>
    </header>

    <main class="finance-container">
        <h1>Finance Tracker</h1>
        <p>Track your finances by adding and subtracting costs with commit messages.</p>

        <form method="POST" action="/add-cost" class="finance-form">
            <label for="commitMessage">За что:</label>
            <input type="text" id="commitMessage" name="commitMessage" placeholder="Enter commit message" required>

            <label for="cost">Сколько:</label>
            <input type="number" id="cost" name="cost" placeholder="Enter cost" required>

            <label for="user">Кто должен:</label>
            <select name="user" id="user" required>
                <option value="Mikitasz">Mikita</option>
                <option value="Ania">Ania</option>
            </select>

            <button type="submit" class="submit-btn">Add Cost</button>
        </form>

        <h2>Commit History</h2>
        <div class="commit-history">
            <ul>
                {{range .CommitMessages}}
                    <li><strong>{{.User}}:</strong> ({{.Time}}): {{.Message}}</li>
                {{end}}
            </ul>
        </div>

        <h2>Financial Summary</h2>
        <p>Никита торчит: <strong>{{.Mikita}}</strong></p>
        <p>Аня торчит: <strong>{{.Ania}}</strong></p>
    </main>
</body>
</html>`

	data := struct {
		Username       string
		CommitMessages []CommitMessage
		Mikita         int
		Ania           int
	}{
		Username:       username,
		CommitMessages: allCommitMessages,
		Mikita:         mikitaSum,
		Ania:           aniaSum,
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

// Function to get user-specific file path
type CommitMessage struct {
	User    string
	Message string
	Time    string
}

// Handle adding a cost and committing to GitHub
func handleAddCost(w http.ResponseWriter, r *http.Request) {
	if !isAllowedIP(r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
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
	costInput := r.FormValue("cost")
	selectedUser := r.FormValue("user") // Get the selected user (either Mikitasz or Ania)
	if selectedUser != "Mikitasz" && selectedUser != "Ania" {
		http.Error(w, "Invalid user selected", http.StatusBadRequest)
		return
	}
	// Конвертируем введенную сумму в число
	costValue, err := strconv.Atoi(costInput)
	if err != nil {
		http.Error(w, "Invalid cost value", http.StatusBadRequest)
		return
	}
	// Если выбран action "subtract", делаем стоимость отрицательной
	filePath := getFileForUser(selectedUser)
	oppositeUser := "Mikitasz"
	if selectedUser == "Mikitasz" {
		oppositeUser = "Ania"
	}
	selectedCurrentCost, err := getCurrentCostFromGitHub(filePath, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get current cost: %v", err), http.StatusInternalServerError)
		return
	}
	filePath2 := getFileForUser(oppositeUser)
	opositeCurrentCost, err := getCurrentCostFromGitHub(filePath2, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get current cost: %v", err), http.StatusInternalServerError)
		return
	}
	if opositeCurrentCost > 0 {
		newCost := opositeCurrentCost - costValue
		if newCost <= 0 {
			// Считаем, сколько нужно перенести в противоположный файл
			transferAmount := -newCost // Лишняя сумма, которую нужно перенести

			newCost := selectedCurrentCost + transferAmount

			// Создаем строку для противоположного пользователя с лишними деньгами
			content := fmt.Sprintf("User: %s\nCost: %d\nMessage: %s\n\n", username, newCost, commitMessage)

			// Коммитим отрицательную сумму в файл другого пользователя
			if err := commitToGitHub(username, selectedUser, commitMessage, content); err != nil {
				http.Error(w, fmt.Sprintf("Failed to commit to opposite file: %v", err), http.StatusInternalServerError)
				return
			}

			content = fmt.Sprintf("User: %s\nCost: %d\nMessage: %s\n\n", username, 0, "update test")

			// Коммитим отрицательную сумму в файл другого пользователя
			if err := commitToGitHub(username, oppositeUser, commitMessage, content); err != nil {
				http.Error(w, fmt.Sprintf("Failed to commit to opposite file: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}
	if opositeCurrentCost == 0 {
		newCost := selectedCurrentCost + costValue

		// Создаем строку для противоположного пользователя с лишними деньгами
		content := fmt.Sprintf("User: %s\nCost: %d\nMessage: %s\n\n", username, newCost, commitMessage)

		// Коммитим отрицательную сумму в файл другого пользователя
		if err := commitToGitHub(username, selectedUser, commitMessage, content); err != nil {
			http.Error(w, fmt.Sprintf("Failed to commit to opposite file: %v", err), http.StatusInternalServerError)
			return
		}

	}

	// Пересчитываем разницу между файлами и отображаем её
	mikitaSum, _ := getCurrentSum("Mikita.txt")
	aniaSum, _ := getCurrentSum("Ania.txt")
	var difference int
	var userWithLess string
	if mikitaSum < aniaSum {
		difference = aniaSum - mikitaSum
		userWithLess = "Mikita"
	} else {
		difference = mikitaSum - aniaSum
		userWithLess = "Ania"
	}

	log.Printf("Difference between sums: %d (User with less: %s)", difference, userWithLess)

	http.Redirect(w, r, "/finance", http.StatusFound)
}

// Функция для получения текущей суммы из файла
func getCurrentSum(filePath string) (int, error) {
	token := userTokens["Mikitasz"] // Предполагаем, что токен есть
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", githubUsername, repoName, filePath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil // Если файла нет, сумма равна 0
	}

	var fileData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fileData); err != nil {
		return 0, err
	}

	// Декодируем содержимое файла
	decodedContent, err := base64.StdEncoding.DecodeString(fileData["content"].(string))
	if err != nil {
		return 0, err
	}

	// Парсим строки и суммируем значения Cost
	lines := bytes.Split(decodedContent, []byte("\n"))
	totalCost := 0
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Cost:")) {
			var cost int
			_, err := fmt.Sscanf(string(line), "Cost: %d", &cost)
			if err == nil {
				totalCost += cost
			}
		}
	}

	return totalCost, nil
}
func getCurrentCostFromGitHub(filePath, username string) (int, error) {
	token, exists := userTokens[username]
	if !exists {
		return 0, fmt.Errorf("user not logged in or token missing")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", githubUsername, repoName, filePath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to fetch file: %s", resp.Status)
	}

	var fileData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fileData); err != nil {
		return 0, err
	}

	// Декодируем содержимое файла из base64
	encodedContent := fileData["content"].(string)
	decodedContent, err := base64.StdEncoding.DecodeString(encodedContent)
	if err != nil {
		return 0, err
	}

	// Ищем строку с текущим Cost
	lines := strings.Split(string(decodedContent), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Cost:") {
			costStr := strings.TrimSpace(strings.TrimPrefix(line, "Cost:"))
			cost, err := strconv.Atoi(costStr)
			if err != nil {
				return 0, err
			}
			return cost, nil
		}
	}

	return 0, fmt.Errorf("cost not found in file")
}

// Function to get user-specific file path
func getFileForUser(username string) string {
	if username == "Mikitasz" {
		return "Mikita.txt"
	}
	return "Ania.txt"
}

// Commit to GitHub
func commitToGitHub(username, selectedUser, message, content string) error {
	filePath := getFileForUser(selectedUser)
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
