# DogGate

![DogGate](doggate.webp)

DogGate, a simple and easy authentication system for your web applications.

Featuring account registration, login, and two-factor authentication.

Passwords are stored as bcrypt hashes in the database and TOTP secrets are encrypted with AES.

## Features

- **Simple**: DogGate is a simple and easy to use authentication system.
- **Secure**: DogGate uses a secure hashing algorithm to store passwords.
- **Fast**: DogGate is fast and lightweight.
- **Easy**: DogGate is easy to use and integrate into your web applications.
- **Free**: DogGate is free and open-source.

## Prerequisites

- Container runtime (Docker, Podman, etc.)
- MySQL or MariaDB database endpoint

## Example Nginx Ingress Manifest

Example Nginx Ingress manifest with DogGate authentication.
Replace doggate-service.doggate-namespace.svc.cluster.local with the DogGate service endpoint.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://doggate-service.doggate-namespace.svc.cluster.local/auth"
spec:
  rules:
  - host: my-app.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: my-service
            port:
              number: 80
```

## Registration Flow

1. User registers an account with their username and password at the `/register` endpoint.
1. DogGate stores the user's username and password in the database.
1. A TOTP QR code is generated for the user.
1. The user scans the TOTP QR code with their authenticator app.

## Login Flow

1. User logs in (basic auth) with their username and password+totp code at the `/auth` endpoint. The TOTP code should be appended to the password, e.g., `password123456`.
1. The entered username and password+totp are valid for 90 days, or until the binary restarts, after which the user must re-authenticate.

## Dev

### Secret Key for TOTP Encryption

```bash
openssl rand -hex 32 > .secret
```

### MariaDB

```bash
mkdir dbdata

podman run --rm \
--name mariadb \
-p 3306:3306 \
-e MYSQL_ROOT_PASSWORD=root \
-e MYSQL_DATABASE=doggate \
-v $(pwd)/dbdata:/var/lib/mysql \
-d mariadb:latest
```

### Run

```bash
MYSQL_ENCRYPTION_KEY=$(cat .secret) \
MYSQL_DSN="root:root@tcp(localhost:3306)/doggate" \
go run .
```
