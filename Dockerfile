FROM golang:1.11

WORKDIR /go/src/github.com/EFForg/starttls-backend

RUN apt-get update && apt-get -y install postgresql-client

# Download vendorized dependencies
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN go mod download

# Build the binary
COPY . .
RUN go install .

ENTRYPOINT ["/go/src/github.com/EFForg/starttls-backend/entrypoint.sh"]
CMD ["/go/bin/starttls-backend"]

EXPOSE 8080
