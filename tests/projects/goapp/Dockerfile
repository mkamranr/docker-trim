FROM golang:1.24

WORKDIR /src

RUN apt-get update && apt-get install -y git make ca-certificates curl

COPY . .

RUN go build -o /src/bin/goapp .

EXPOSE 8080
CMD ["/src/bin/goapp"]
