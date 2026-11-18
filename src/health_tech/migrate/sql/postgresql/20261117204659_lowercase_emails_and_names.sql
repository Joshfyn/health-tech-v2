-- Emails and names are stored in lower case, so Sam@example.com and sam@example.com are one
-- email. The services lower-case them on every write; this converts the rows already stored.
--
-- Fails, and changes nothing, if lower-casing would give two logins the same email and role
-- (the unique index uq_role_accounts_email_role refuses it). Resolve those first; see README.

UPDATE users
SET email = lower(email),
    first_name = lower(first_name),
    last_name = lower(last_name)
WHERE email <> lower(email)
   OR first_name <> lower(first_name)
   OR last_name <> lower(last_name);

UPDATE role_accounts
SET email = lower(email)
WHERE email <> lower(email);
