FROM golang:1.24

WORKDIR /src

RUN apt-get update && apt-get install -y git make ca-certificates

COPY . .

RUN go build -o /src/bin/api ./cmd/api

EXPOSE 8080
CMD ["/src/bin/api"]
