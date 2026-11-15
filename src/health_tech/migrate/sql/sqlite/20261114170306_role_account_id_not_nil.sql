-- Give role accounts created without an ID their own ID, then reject the nil ID.
-- SQLite cannot add a CHECK constraint to an existing table, so triggers enforce it.

-- Random version 4 UUID in the 32-character hex form SQLAlchemy stores.
UPDATE role_accounts
SET role_account_id = lower(
    hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2)
    || substr('89ab', 1 + abs(random() % 4), 1) || substr(hex(randomblob(2)), 2)
    || hex(randomblob(6))
)
WHERE role_account_id IS NULL
   OR role_account_id = '00000000000000000000000000000000';

CREATE TRIGGER IF NOT EXISTS role_accounts_role_account_id_not_nil_insert
BEFORE INSERT ON role_accounts
WHEN NEW.role_account_id IS NULL
  OR NEW.role_account_id = '00000000000000000000000000000000'
BEGIN
    SELECT RAISE(ABORT, 'role_account_id must not be nil');
END;

CREATE TRIGGER IF NOT EXISTS role_accounts_role_account_id_not_nil_update
BEFORE UPDATE OF role_account_id ON role_accounts
WHEN NEW.role_account_id IS NULL
  OR NEW.role_account_id = '00000000000000000000000000000000'
BEGIN
    SELECT RAISE(ABORT, 'role_account_id must not be nil');
END;
