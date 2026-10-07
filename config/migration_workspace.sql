CREATE TABLE IF NOT EXISTS attendance (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id INT UNSIGNED NOT NULL,
 work_date DATE NOT NULL, clock_in DATETIME NOT NULL, clock_out DATETIME NULL,
 UNIQUE KEY one_attendance_day(user_id,work_date),
 FOREIGN KEY(user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS leave_requests (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id INT UNSIGNED NOT NULL,
 leave_type ENUM('annual','sick','personal') NOT NULL, start_date DATE NOT NULL, end_date DATE NOT NULL,
 reason VARCHAR(1000) NOT NULL, status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
 reviewer_id INT UNSIGNED NULL, review_note VARCHAR(1000) NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 KEY user_status(user_id,status), FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(reviewer_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS performance_goals (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id INT UNSIGNED NOT NULL,
 title VARCHAR(200) NOT NULL, due_date DATE NOT NULL, progress TINYINT UNSIGNED NOT NULL DEFAULT 0,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP, KEY user_goals(user_id),
 FOREIGN KEY(user_id) REFERENCES users(id), CHECK(progress <= 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
