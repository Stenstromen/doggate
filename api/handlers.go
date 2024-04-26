package api

import (
	"encoding/json"
	"net/http"

	"github.com/stenstromen/doggate/db"
	model "github.com/stenstromen/doggate/model"
)

func Handlers(db *db.DB) *http.ServeMux {

	r := http.NewServeMux()

	r.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		loginPage := db.LoginHandler()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(loginPage))
	})

	r.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var userRequest model.UserRequest
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

	r.HandleFunc("DELETE /delete/{username}", func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		if username == "" {
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		res, err := db.DeleteUser(username)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)

	})

	r.HandleFunc("GET /register", func(w http.ResponseWriter, r *http.Request) {
		registerPage := db.RegistrationHandler()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(registerPage))
	})

	r.HandleFunc("POST /auth", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		auth, err := db.AuthenticateHandler(w, r, username, password)

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

	r.HandleFunc("POST /verify-otp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.Form.Get("username")
		otp := r.Form.Get("otp")

		if username == "" || otp == "" {
			http.Error(w, "Username and OTP are required", http.StatusBadRequest)
			return
		}

		auth := db.VerifyOtpHandler(w, r, username, otp)

		if !auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)

	})

	r.HandleFunc("GET /validate", func(w http.ResponseWriter, r *http.Request) {
		session := db.ValidateSessionHandler(w, r)

		if !session {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	return r
}