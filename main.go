package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username   string
	Password   string
	TOTPSecret string
}

var (
	store = sessions.NewCookieStore([]byte("very-secret-key"))
	users = map[string]string{}
)

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		w.WriteHeader(http.StatusOK)
		return
	}

	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if user, ok := users[username]; ok {
		err := bcrypt.CompareHashAndPassword([]byte(user), []byte(password))
		if err == nil {
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Save(r, w)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Login successful"))
			return
		}
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "YourApp",
		AccountName: user.Username,
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}
	user.TOTPSecret = totpSecret.Secret()

	users[user.Username] = user.Password
	json.NewEncoder(w).Encode(user)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl := template.Must(template.New("login").Parse(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
        </head>
        <body>
            <h2>Login</h2>
            <form action="/auth" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    `))
	tmpl.Execute(w, nil)
}

func main() {
	r := http.NewServeMux()
	r.HandleFunc("POST /register", RegisterHandler)
	r.HandleFunc("GET /login", LoginHandler)
	r.HandleFunc("/auth", AuthenticateHandler)
	log.Fatal(http.ListenAndServe(":8080", r))
}
