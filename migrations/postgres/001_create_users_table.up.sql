CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar(128) UNIQUE,
    password_hash bytea,
    salt bytea,
    enc_salt bytea,
    created_at timestamp DEFAULT now()
);