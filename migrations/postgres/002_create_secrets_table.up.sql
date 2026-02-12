CREATE TABLE secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid references users(id),
    encrypted_data bytea,
    nonce bytea,
    created_at timestamp DEFAULT now()
);