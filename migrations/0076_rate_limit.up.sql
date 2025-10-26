ALTER TABLE projects
  ADD COLUMN rate_limit INT NOT NULL DEFAULT 0 AFTER user_agent;

