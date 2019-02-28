-- Create all tables.

CREATE TABLE IF NOT EXISTS tokens
(
    domain      TEXT NOT NULL PRIMARY KEY,
    token       VARCHAR(255) NOT NULL,
    expires     TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE
);


CREATE TABLE IF NOT EXISTS scans
(
    id          SERIAL PRIMARY KEY,
    domain      TEXT NOT NULL,
    scandata    TEXT NOT NULL,
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hostname_scans
(
    id          SERIAL PRIMARY KEY,
    hostname    TEXT NOT NULL,
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status      SMALLINT,
    scandata    TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS domains
(
    domain       TEXT NOT NULL UNIQUE PRIMARY KEY,
    email        TEXT NOT NULL,
    data         TEXT NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status       VARCHAR(255) NOT NULL
);


CREATE TABLE IF NOT EXISTS blacklisted_emails
(
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    reason      TEXT NOT NULL,
    timestamp   TIMESTAMP
);

-- Schema change: add "last_updated" timestamp column if it doesn't exist.

ALTER TABLE domains ADD COLUMN IF NOT EXISTS last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create trigger to ensure last_updated is updated every time
-- the corresponding row changes.

CREATE OR REPLACE FUNCTION update_changetimestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
        NEW.last_updated = now();
        RETURN NEW;
    ELSE
        RETURN OLD;
    END IF;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_change_timestamp ON domains;

CREATE TRIGGER update_change_timestamp BEFORE UPDATE
    ON domains FOR EACH ROW EXECUTE PROCEDURE
    update_changetimestamp_column();

ALTER TABLE scans ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 0;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS mta_sts_mode TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS domain_totals
(
    id              SERIAL PRIMARY KEY,
    time            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source          TEXT NOT NULL,
    attempted       INTEGER DEFAULT 0,
    connected       INTEGER DEFAULT 0,
    mta_sts_testing INTEGER DEFAULT 0,
    mta_sts_enforce INTEGER DEFAULT 0
);
