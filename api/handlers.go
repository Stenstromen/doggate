package api

import (
	"net/http"

	"github.com/stenstromen/doggate/db"
)

func Handlers(db *db.DB) *http.ServeMux {

	r := http.NewServeMux()

	r.HandleFunc("POST /register", db.RegisterHandler())
	r.HandleFunc("GET /register", RegistrationHandler)
	r.HandleFunc("GET /login", LoginHandler)
	r.HandleFunc("/auth", AuthenticateHandler)
	r.HandleFunc("/otp", OtpHandler)
	r.HandleFunc("/verify-otp", VerifyOtpHandler)
	r.HandleFunc("/validate", ValidateSessionHandler)

	return r

}
