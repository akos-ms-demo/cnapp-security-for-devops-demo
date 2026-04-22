CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO users (username, password) VALUES ('alice', 'password123');
INSERT INTO users (username, password) VALUES ('bob',   'hunter2');
