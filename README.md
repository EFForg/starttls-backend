# starttls-scanner

## Setup
Requires `go` and `postgres` installations. You can specify the following environment variables:
 - `PORT`, e.g. `:8080`, to specify which port to listen for requests on
 - `DB_HOST`, e.g. `localhost`, to specify the hostname for postgres.
 - `DB_NAME`, e.g. `starttls` or `starttls_dev`, to specify the name of the database. (this should be created in advance!)
 - `DB_USERNAME` / `DB_PASSWORD` - username and password for database access.

`
go get github.com/sydneyli/starttls-scanner
cd $GOPATH/github.com/sydneyli/starttls-scanner
`

You'll also want to ensure `postgres` is running, then run `db/scripts/init_db.sql` in the appropriate postgres DB in order to initialize your database.
Then, you can run:
```
go build
./starttls-scanner
```
to start serving requests at `PORT`.

### Via Docker
Run `docker-compose build`, followed by `docker-compose up`.

## Testing
```
# Service tests
go test -v

# Database tests
go test ./db -v
```
