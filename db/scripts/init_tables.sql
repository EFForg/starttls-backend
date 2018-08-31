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
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS domains
(
    domain       TEXT NOT NULL UNIQUE PRIMARY KEY,
    email        TEXT NOT NULL,
    data         TEXT NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    status       VARCHAR(255) NOT NULL
);

-- Schema change: add "last_updated" timestamp column if it doesn't exist.

ALTER TABLE domains ADD COLUMN IF NOT EXISTS last_update ADD COLUMN
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create trigger to ensure last_updated is updated every time
-- the corresponding row changes.

CREATE OR REPLACE FUNCTION update_changetimestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_update = now();
    RETURN NEW;
END;
$$ language 'plpgsql'

CREATE TRIGGER update_change_timestamp BEFORE UPDATE
ON domains FOR EACH ROW EXECUTE PROCEDURE
update_changetimestamp_column();
