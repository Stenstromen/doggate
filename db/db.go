package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var encryptionKey string

type DB struct {
	Conn *sql.DB
}

func New(dsn string) (*DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return &DB{Conn: db}, nil
}

func (db *DB) ConnectionCheck() error {
	if err := db.Conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}
	return nil
}

func (db *DB) InitializeDB() error {
	encryptionKey = os.Getenv("MYSQL_ENCRYPTION_KEY")
	if encryptionKey == "" {
		return fmt.Errorf("encryption key not set")
	}

	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		return fmt.Errorf("MYSQL_DSN environment variable is not set")
	}

	if err := db.Conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
		password VARCHAR(255) NOT NULL,
		totp_secret VARBINARY(256) NOT NULL
    );`

	if _, err := db.Conn.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}
