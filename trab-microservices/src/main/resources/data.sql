
CREATE TABLE UserTable (
  userId INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(30) NOT NULL,
  senha VARCHAR(10) NOT NULL,
  totalLogins INT DEFAULT 0 NOT NULL,
  totalFails INT DEFAULT 0 NOT NULL,
  blocked BOOLEAN DEFAULT FALSE NOT NULL
);
COMMIT;