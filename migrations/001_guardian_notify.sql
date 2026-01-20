CREATE TABLE users (
  id uuid PRIMARY KEY,
  created_at timestamp NOT NULL,
  updated_at timestamp NOT NULL
);

CREATE TABLE user_identities (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  provider varchar(32) NOT NULL,
  external_id varchar(255) NOT NULL,
  display_hint varchar(255),
  created_at timestamp NOT NULL,
  UNIQUE (provider, external_id)
);

CREATE TABLE sms_challenges (
  id uuid PRIMARY KEY,
  phone_e164 varchar(32),
  phone_hash varchar(128) NOT NULL,
  code_hash varchar(128) NOT NULL,
  purpose varchar(32) NOT NULL,
  expires_at timestamp NOT NULL,
  tries_left integer NOT NULL,
  created_at timestamp NOT NULL,
  consumed_at timestamp
);

CREATE TABLE guardian_links (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  child_id uuid NOT NULL,
  linked_via varchar(32) NOT NULL,
  valid_from date NOT NULL,
  valid_to date,
  is_active boolean NOT NULL,
  created_at timestamp NOT NULL,
  updated_at timestamp NOT NULL,
  UNIQUE (user_id, child_id)
);

CREATE TABLE notification_threads (
  id uuid PRIMARY KEY,
  child_id uuid NOT NULL,
  status varchar(16) NOT NULL,
  created_by_staff_id varchar(64),
  created_at timestamp NOT NULL,
  updated_at timestamp NOT NULL
);

CREATE TABLE notification_messages (
  id uuid PRIMARY KEY,
  thread_id uuid NOT NULL REFERENCES notification_threads(id),
  sender_type varchar(16) NOT NULL,
  sender_id varchar(64) NOT NULL,
  body_text text NOT NULL,
  created_at timestamp NOT NULL
);

CREATE TABLE notification_reads (
  id uuid PRIMARY KEY,
  thread_id uuid NOT NULL REFERENCES notification_threads(id),
  reader_type varchar(16) NOT NULL,
  reader_id varchar(64) NOT NULL,
  last_read_at timestamp NOT NULL,
  UNIQUE (thread_id, reader_type, reader_id)
);

CREATE TABLE notify_qr_tokens (
  id uuid PRIMARY KEY,
  thread_id uuid NOT NULL,
  child_id uuid NOT NULL,
  expires_at timestamp NOT NULL,
  nonce varchar(64) NOT NULL,
  consumed_at timestamp,
  created_at timestamp NOT NULL
);
