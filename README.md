# DogGate

![DogGate](doggate.webp)

DogGate, a simple and easy authentication system for your web applications.

Featuring account registration, login, and validation.

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
    nginx.ingress.kubernetes.io/auth-url: "http://doggate-service.doggate-namespace.svc.cluster.local/validate"
    nginx.ingress.kubernetes.io/auth-signin: "http://doggate-service.doggate-namespace.svc.cluster.local/login"
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

## Dev

### Secret Key for Cookie Store

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
SESSION_SECRET_KEY=$(cat .secret) \
MYSQL_DSN="root:root@tcp(localhost:3306)/doggate" \
go run .
```
