-- Account scoped technology catalogue preferences. Existing inventory and watchlists remain unchanged.
CREATE TABLE IF NOT EXISTS user_technology_catalogue (
  user_id TEXT PRIMARY KEY,
  preferences_json TEXT NOT NULL CHECK(length(preferences_json) <= 18000),
  updated_at INTEGER NOT NULL
);
