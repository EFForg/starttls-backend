FROM golang:1.10

WORKDIR /go/src/github.com/EFForg/starttls-backend

RUN apt-get update && apt-get -y install postgresql-client

ADD . .

RUN go get github.com/EFForg/starttls-backend

ENTRYPOINT ["/go/src/github.com/EFForg/starttls-backend/entrypoint.sh"]
CMD ["/go/bin/starttls-backend"]

EXPOSE 8080
