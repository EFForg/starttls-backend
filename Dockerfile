FROM golang:1.8

WORKDIR /go/src/github.com/EFForg/starttls-scanner

ADD . .

RUN go get github.com/EFForg/starttls-scanner

ENTRYPOINT /go/bin/starttls-scanner

EXPOSE 8080
