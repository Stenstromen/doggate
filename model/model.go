package model

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
