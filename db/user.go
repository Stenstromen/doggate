package db

import (
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	model "github.com/stenstromen/doggate/model"
)

var store *sessions.CookieStore

func init() {
	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("SESSION_SECRET_KEY environment variable is not set or empty")
	}

	store = sessions.NewCookieStore([]byte(secretKey))
}

func (db *DB) VerifyOtpHandler(w http.ResponseWriter, r *http.Request, username, otp string) bool {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return false
	}

	var totpSecret string
	err = db.Conn.QueryRow("SELECT totp_secret FROM users WHERE username = ?", username).Scan(&totpSecret)
	if err != nil {
		if err == sql.ErrNoRows {
			session.AddFlash("User not found")
			session.Save(r, w)
			return false
		}

		log.Printf("Error retrieving user TOTP secret: %v", err)
		session.AddFlash("Internal server error")
		session.Save(r, w)
		return false
	}

	valid := totp.Validate(otp, totpSecret)
	if !valid {
		session.AddFlash("Invalid OTP")
		session.Save(r, w)
		return false
	}

	session.Values["authenticated"] = true
	session.Values["username"] = username
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		return false
	}

	return true
}

func (db *DB) OtpHandler(username string) string {
	tmplString := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enter OTP</title>
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
        <h2>Enter OTP</h2>
        <form action="/verify-otp" method="post">
            <input type="hidden" name="username" value="{{.Username}}">
            <label for="otp">OTP:</label>
            <input type="text" id="otp" name="otp" required><br><br>
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>`

	tmpl, err := template.New("otp").Parse(tmplString)
	if err != nil {
		log.Fatal("Error parsing template:", err)
	}

	data := model.PageData{Username: username}
	var tplBuffer bytes.Buffer
	if err := tmpl.Execute(&tplBuffer, data); err != nil {
		log.Fatal("Error executing template:", err)
	}

	return tplBuffer.String()
}

func (db *DB) AuthenticateHandler(w http.ResponseWriter, r *http.Request, username, password string) (bool, error) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return false, fmt.Errorf("error retrieving session: %v", err)
	}

	var hashedPassword string
	err = db.Conn.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			session.AddFlash("Invalid username or password")
			session.Save(r, w)
			return false, nil
		}

		return false, fmt.Errorf("database error: %v", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		session.AddFlash("Invalid username or password")
		session.Save(r, w)
		return false, nil
	}

	session.Values["authenticated"] = true
	session.Values["username"] = username
	if err := session.Save(r, w); err != nil {
		return false, fmt.Errorf("failed to save session: %v", err)
	}

	return true, nil
}

func (db *DB) RegisterHandler(username, password string) (model.User, error) {
	var user model.User
	user.Username = username

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	user.Password = string(hashedPassword)

	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DogGate",
		AccountName: username,
	})
	if err != nil {
		return model.User{}, err
	}
	user.TOTPSecret = totpSecret.Secret()

	_, err = db.Conn.Exec("INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)", username, user.Password, user.TOTPSecret)
	if err != nil {
		return model.User{}, err
	}

	return user, nil
}

func (db *DB) LoginHandler() string {
	tmplString := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login</title>
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
			<h2>Login</h2>
			<form action="/auth" method="post">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required>
				<button type="submit">Login</button>
			</form>
		</div>
	</body>
	</html>
		`

	return tmplString
}

func (db *DB) ValidateSessionHandler(w http.ResponseWriter, r *http.Request) bool {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
	}

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		return true
	}

	return false
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
