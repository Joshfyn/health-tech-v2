-- One login per email and role: sign in names both, so a second account with the same pair
-- would leave it unable to tell which login is meant.
-- Fails, and changes nothing, while duplicates exist. Resolve them first; see README.

CREATE UNIQUE INDEX IF NOT EXISTS uq_role_accounts_email_role ON role_accounts (email, role);
