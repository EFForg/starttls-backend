FROM golang:1.11-alpine

WORKDIR /go/src/github.com/EFForg/starttls-backend/checker

RUN apk add git

ADD . .

RUN go get github.com/EFForg/starttls-backend/checker/cmd/starttls-check

CMD ["/go/bin/starttls-check"]
