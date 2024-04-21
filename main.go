package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username   string
	Password   string
	TOTPSecret string
}

var (
	store = sessions.NewCookieStore([]byte("very-secret-key"))
	users = map[string]*User{}
)

func VerifyOtpHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.Form.Get("username")
	otp := r.Form.Get("otp")

	user, ok := users[username]
	if !ok {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	valid := totp.Validate(otp, user.TOTPSecret)
	if !valid {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Save(r, w)
	w.Write([]byte("OTP verified, logged in successfully"))
}

func OtpHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("otp").Parse(`
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
</html>
    `))
	tmpl.Execute(w, map[string]interface{}{
		"Username": r.URL.Query().Get("username"),
	})
}

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	user, ok := users[username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/otp?username="+username, http.StatusSeeOther)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DogGate",
		AccountName: user.Username,
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}
	user.TOTPSecret = totpSecret.Secret()

	users[user.Username] = &user
	json.NewEncoder(w).Encode(user)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl := template.Must(template.New("login").Parse(`
<!DOCTYPE html>
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
    `))
	tmpl.Execute(w, nil)
}

func ValidateSessionHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("register").Parse(`
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
								  '<br>Scan the QR code with your TOTP app.</p>';
	
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
        `))
	tmpl.Execute(w, nil)
}

func main() {
	r := http.NewServeMux()
	r.HandleFunc("POST /register", RegisterHandler)
	r.HandleFunc("GET /register", RegistrationHandler)
	r.HandleFunc("GET /login", LoginHandler)
	r.HandleFunc("/auth", AuthenticateHandler)
	r.HandleFunc("/otp", OtpHandler)
	r.HandleFunc("/verify-otp", VerifyOtpHandler)
	r.HandleFunc("/validate", ValidateSessionHandler)
	log.Fatal(http.ListenAndServe(":8080", r))
}
