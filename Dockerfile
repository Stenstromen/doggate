FROM golang:1.22-alpine as build
WORKDIR /
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags='-w -s' -o /doggate

FROM alpine:latest
COPY --from=build /doggate /
EXPOSE 8080
CMD [ "/doggate" ]