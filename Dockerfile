FROM golang:1.8

ADD . /go/src/github.com/sydneyli/starttls-scanner

RUN go get github.com/sydneyli/starttls-scanner
RUN go install github.com/sydneyli/starttls-scanner

ENTRYPOINT /go/bin/starttls-scanner

EXPOSE 8080

