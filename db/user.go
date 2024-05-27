package db

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	model "github.com/stenstromen/doggate/model"
)

func (db *DB) AuthenticateHandler(username, passwordAndOTP string) (bool, error) {
	var obfuscatedPassword string
	err := db.Conn.QueryRow("SELECT AES_DECRYPT(password, ?) FROM sessions WHERE username = ?", encryptionKey, username).Scan(&obfuscatedPassword)

	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(username, "username not found in sessions, proceeding with authentication...")
		} else {
			log.Printf("Error retrieving user password: %v", err)
			return false, err
		}
	} else {
		decodedPassword, err := base64.URLEncoding.DecodeString(obfuscatedPassword)
		if err != nil {
			log.Printf("Error decoding password: %v", err)
			return false, err
		}
		passwordAndOTPFromDB := string(decodedPassword)

		if passwordAndOTP != passwordAndOTPFromDB {
			fmt.Println(username, "password mismatch, re-authenticating...")
			return false, nil
		}

		var timestampStr string
		err = db.Conn.QueryRow("SELECT CAST(timestamp AS CHAR) FROM sessions WHERE username = ?", username).Scan(&timestampStr)
		if err != nil {
			log.Printf("Error retrieving session timestamp: %v", err)
			return false, err
		}

		timestamp, err := time.Parse("2006-01-02 15:04:05", timestampStr)
		if err != nil {
			log.Printf("Error parsing session timestamp: %v", err)
			return false, err
		}

		if time.Since(timestamp) > 30*24*time.Hour {
			fmt.Println(username, "session expired, re-authenticating...")
			return false, nil
		}

		fmt.Println(username, "authenticated successfully")
		return true, nil
	}

	fmt.Println("Proceeding with authentication...")

	otp := passwordAndOTP[len(passwordAndOTP)-6:]
	password := passwordAndOTP[:len(passwordAndOTP)-6]

	var hashedPassword string
	err = db.Conn.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("database error: %v", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return false, nil
	}

	var totpSecret string
	err = db.Conn.QueryRow("SELECT AES_DECRYPT(totp_secret, ?) FROM users WHERE username = ?", encryptionKey, username).Scan(&totpSecret)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		log.Printf("Error retrieving user TOTP secret: %v", err)
		return false, nil
	}

	valid := totp.Validate(otp, totpSecret)
	if !valid {
		return false, nil
	}

	obfuscatedPassword = base64.URLEncoding.EncodeToString([]byte(passwordAndOTP))
	_, err = db.Conn.Exec("INSERT INTO sessions (username, password, timestamp) VALUES (?, AES_ENCRYPT(?, ?), ?)", username, obfuscatedPassword, encryptionKey, time.Now())
	if err != nil {
		log.Printf("Error inserting session into database: %v", err)
		return false, err
	}

	return true, nil
}

func (db *DB) RegisterHandler(username, password string) (model.User, error) {
	var user model.User
	user.Username = username

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error generating password hash:", err)
		return model.User{}, err
	}
	user.Password = string(hashedPassword)

	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DogGate",
		AccountName: username,
	})
	if err != nil {
		fmt.Println("Error generating TOTP secret:", err)
		return model.User{}, err
	}
	user.TOTPSecret = totpSecret.Secret()

	_, err = db.Conn.Exec("INSERT INTO users (username, password, totp_secret) VALUES (?, ?, AES_ENCRYPT(?, ?))", username, user.Password, totpSecret.Secret(), encryptionKey)
	if err != nil {
		fmt.Println("Error inserting user into database:", err)
		return model.User{}, err
	}

	return user, nil
}

func (db *DB) DeleteUser(username string) (bool, error) {
	_, err := db.Conn.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (db *DB) RegistrationHandler() string {
	tmpl := `
	<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f4f4f4;
        }
        .login-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            width: 300px;
        }
        form {
            display: flex;
            flex-direction: column;
        }
        label {
            margin-bottom: 5px;
        }
        input[type="text"], input[type="password"] {
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
<div class="login-box">
    <h2>Register</h2>
    <form id="registerForm">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <button type="submit">Register</button>
    </form>
    <div id="result" style="margin-top: 20px;"></div>
</div>
<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs/qrcode.min.js"></script>
<script>
document.getElementById('registerForm').onsubmit = function(e) {
    e.preventDefault();
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username: username, password: password })
    })
    .then(response => response.json())
    .then(data => {
        var resultDiv = document.getElementById('result');
        var issuer = 'DogGate';
        var otpAuthUrl = 'otpauth://totp/' + issuer + ':' + username + '?secret=' + data.TOTPSecret + '&issuer=' + issuer;

        resultDiv.innerHTML = '<p>Registration successful!<br>Username: ' + username +
                              '<br>Scan the QR code with your TOTP app or enter this key manually: <strong>' + data.TOTPSecret + '</strong></p>';

        var qrDiv = document.createElement('div');
        resultDiv.appendChild(qrDiv);
        new QRCode(qrDiv, {
            text: encodeURI(otpAuthUrl),
            width: 128,
            height: 128,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        });
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('result').innerHTML = '<p style="color: red;">Registration failed!</p>';
    });
};
</script>
</body>
</html>
        `

	return tmpl
}
