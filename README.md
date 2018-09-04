# starttls-backend

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
