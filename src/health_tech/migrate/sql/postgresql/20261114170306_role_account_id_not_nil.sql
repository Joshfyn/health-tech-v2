-- Give role accounts created without an ID their own ID, then reject the nil ID.

UPDATE role_accounts
SET role_account_id = gen_random_uuid()
WHERE role_account_id IS NULL
   OR role_account_id = '00000000-0000-0000-0000-000000000000';

ALTER TABLE role_accounts ALTER COLUMN role_account_id SET NOT NULL;

ALTER TABLE role_accounts DROP CONSTRAINT IF EXISTS ck_role_accounts_role_account_id_not_nil;
ALTER TABLE role_accounts ADD CONSTRAINT ck_role_accounts_role_account_id_not_nil
    CHECK (role_account_id <> '00000000-0000-0000-0000-000000000000');
