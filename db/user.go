package db

func (db *DB) CreateUser(username, password, totpSecret string) error {
	insertUserSQL := `
	INSERT INTO users (username, password, totp_secret)
	VALUES (?, ?, ?);`

	_, err := db.Conn.Exec(insertUserSQL, username, password, totpSecret)
	return err
}

func (db *DB) GetUser(username string) (string, string, string, error) {
	selectUserSQL := `
	SELECT username, password, totp_secret
	FROM users
	WHERE username = ?;`

	var u, p, t string
	err := db.Conn.QueryRow(selectUserSQL, username).Scan(&u, &p, &t)
	return u, p, t, err
}

func (db *DB) DeleteUser(username string) error {
	deleteUserSQL := `
	DELETE FROM users
	WHERE username = ?;`

	_, err := db.Conn.Exec(deleteUserSQL, username)
	return err
}
