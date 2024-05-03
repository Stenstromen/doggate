package model

import "time"

type User struct {
	Username   string
	Password   string
	TOTPSecret string
}

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PageData struct {
	Username string
}

type AuthUser struct {
	Username  string
	Password  string
	Timestamp time.Time
}

type Users []AuthUser
