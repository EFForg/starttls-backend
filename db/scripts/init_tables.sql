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
    last_updated TIMESTAMP,
    status       VARCHAR(255) NOT NULL
);
