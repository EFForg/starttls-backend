# starttls-backend

[![Build Status](https://travis-ci.com/EFForg/starttls-backend.svg?branch=master)](https://travis-ci.org/EFForg/starttls-backend)
[![Coverage Status](https://coveralls.io/repos/github/EFForg/starttls-backend/badge.svg?branch=master)](https://coveralls.io/github/EFForg/starttls-backend?branch=master)

## Setup
1. Install `go` and `postgres`.
2. Download the project and copy the configuration file:
```
go get github.com/EFForg/starttls-backend
cd $GOPATH/github.com/EFForg/starttls-backend
cp .env.example .env
cp .env.test.example .env.test
```
3. Edit `.env` and `.env.test` with your postgres credentials and any other changes.
4. Ensure `postgres` is running, then run `db/scripts/init_tables.sql` in the appropriate postgres DBs in order to initialize your development and test databases.
5. Build the scanner and start serving requests:
```
go build
./starttls-backend
```

### Via Docker
```
cp .env.example .env
cp .env.test.example .env.test
docker-compose build
docker-compose up
```

## Performing database migrations
```
docker-compose exec <DB_CONTAINER> sh -c \
'psql -U $DB_USERNAME $DB_NAME -f ./docker-entrypoint-initdb.d/init_tables.sql'
```
Where `<DB_CONTAINER>` is the name of the container; in the setup we have outlined here, this would either be `postgres` or `postgres_test`.

## Testing
# Service tests
```
docker-compose exec app go test -v
```

# Database tests
```
docker-compose exec app go test ./db -v
```

### No-scan domains
In case of complaints or abuse, we may not want to continually scan some domains. You can set the environment variable `DOMAIN_BLACKLIST` to point to a file with a list of newline-separated domains. Attempting to scan those domains from the public-facing website will result in error codes.
