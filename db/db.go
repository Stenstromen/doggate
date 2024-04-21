package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

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
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		return fmt.Errorf("MYSQL_DSN environment variable is not set")
	}

	if err := db.Conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	createTableSQL := `
    CREATE TABLE IF NOT EXISTS token (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
		password VARCHAR(255) NOT NULL,
		totp_secret VARCHAR(255) NOT NULL
    );`

	if _, err := db.Conn.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}
