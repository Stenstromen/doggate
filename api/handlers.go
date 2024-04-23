package api

import (
	"encoding/json"
	"net/http"

	"github.com/stenstromen/doggate/db"
)

type User struct {
	Username   string
	Password   string
	TOTPSecret string
}

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Handlers(db *db.DB) *http.ServeMux {

	r := http.NewServeMux()

	r.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var userRequest UserRequest
		if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user, err := db.RegisterHandler(userRequest.Username, userRequest.Password)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)

	})
	r.HandleFunc("POST /auth", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		auth, err := db.AuthenticateHandler(username, password)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if auth {
			http.Redirect(w, r, "/otp?username="+username, http.StatusSeeOther)
		}
	})
	r.HandleFunc("GET /otp", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		otpPage := db.OtpHandler(username)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(otpPage))
	})

	/* 	r.HandleFunc("GET /register", RegistrationHandler)
	   	r.HandleFunc("GET /login", LoginHandler)
	   	r.HandleFunc("/auth", AuthenticateHandler)
	   	r.HandleFunc("/otp", OtpHandler)
	   	r.HandleFunc("/verify-otp", VerifyOtpHandler)
	   	r.HandleFunc("/validate", ValidateSessionHandler) */

	return r

}
