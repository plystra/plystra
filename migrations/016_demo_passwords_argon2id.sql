-- Update local demo users to the v1.0 canonical Argon2id password format.

UPDATE users
SET password_hash = 'argon2id$v=19$m=65536,t=3,p=2$cGx5c3RyYS1hbGljZS12MQ$ChTdO8Md0I+wjbQpSbWY+0dkIjCUtkCEQ4taCPbznTU',
	updated_at = now()
WHERE id = 'user_alice';

UPDATE users
SET password_hash = 'argon2id$v=19$m=65536,t=3,p=2$cGx5c3RyYS1ib2ItdjEhIQ$s4mmVEjf6+Q97qeutYCUbmlbfrB+8QT/iVc0mUCTU0s',
	updated_at = now()
WHERE id = 'user_bob';
