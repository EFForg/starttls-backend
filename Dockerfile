FROM golang:1.8

ADD . /go/src/github.com/EFForg/starttls-scanner

RUN go get github.com/EFForg/starttls-scanner
RUN go install github.com/EFForg/starttls-scanner

ENTRYPOINT /go/bin/starttls-scanner

EXPOSE 8080

