CREATE TABLE firewall_subscribers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  confirmation_hash TEXT UNIQUE,
  requested_at INTEGER NOT NULL,
  confirmed_at INTEGER,
  unsubscribe_token TEXT NOT NULL UNIQUE
);
CREATE TABLE firewall_digest_deliveries (
  subscriber_id TEXT NOT NULL REFERENCES firewall_subscribers(id) ON DELETE CASCADE,
  day TEXT NOT NULL,
  claimed_at INTEGER NOT NULL,
  accepted_at INTEGER,
  provider_id TEXT,
  PRIMARY KEY (subscriber_id, day)
);
CREATE INDEX firewall_subscriber_confirmed ON firewall_subscribers(confirmed_at);

