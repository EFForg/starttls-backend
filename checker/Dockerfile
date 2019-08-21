FROM getsentry/sentry-cli AS sentry

FROM golang:1.11-alpine

WORKDIR /go/src/github.com/EFForg/starttls-backend/checker

RUN apk add git

COPY --from=sentry /bin/sentry-cli /bin

COPY . .

RUN go get github.com/EFForg/starttls-backend/checker/cmd/starttls-check

CMD ["/go/bin/starttls-check"]
