FROM postgres:10

# Initialize starttls tables
ADD scripts/init_tables.sql /docker-entrypoint-initdb.d/
