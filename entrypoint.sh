#!/bin/sh

if [ "$DB_MIGRATE" = "true" ]; then
    # Perform ouststanding DB migrations
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USERNAME $DB_NAME -f ./db/scripts/init_tables.sql
fi

exec "$@"
