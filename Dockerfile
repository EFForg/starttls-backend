FROM golang:1.10

WORKDIR /go/src/github.com/EFForg/starttls-backend

ADD . .

RUN go get github.com/EFForg/starttls-backend

ENTRYPOINT /go/bin/starttls-backend

EXPOSE 8080
