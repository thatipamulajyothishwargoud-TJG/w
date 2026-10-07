CREATE TABLE IF NOT EXISTS leave_policies (
 leave_type ENUM('annual','sick','personal') PRIMARY KEY,
 annual_days DECIMAL(5,1) NOT NULL,
 updated_by INT UNSIGNED NULL,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 FOREIGN KEY(updated_by) REFERENCES users(id), CHECK(annual_days>=0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT IGNORE INTO leave_policies(leave_type,annual_days) VALUES('annual',20),('sick',10),('personal',5);
CREATE TABLE IF NOT EXISTS performance_reviews (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 employee_id INT UNSIGNED NOT NULL, reviewer_id INT UNSIGNED NOT NULL,
 cycle VARCHAR(120) NOT NULL, due_date DATE NOT NULL,
 status ENUM('open','submitted','completed') NOT NULL DEFAULT 'open',
 self_assessment TEXT NULL, reviewer_feedback TEXT NULL,
 rating TINYINT UNSIGNED NULL, development_plan TEXT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 KEY employee_status(employee_id,status),
 FOREIGN KEY(employee_id) REFERENCES users(id), FOREIGN KEY(reviewer_id) REFERENCES users(id),
 CHECK(rating IS NULL OR rating BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS announcements (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 title VARCHAR(200) NOT NULL, body TEXT NOT NULL,
 audience ENUM('everyone','employees','admins') NOT NULL DEFAULT 'everyone',
 author_id INT UNSIGNED NOT NULL, is_archived TINYINT(1) NOT NULL DEFAULT 0,
 published_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(author_id) REFERENCES users(id), KEY visible_announcements(is_archived,audience)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS recruitment_candidates (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, job_id INT UNSIGNED NOT NULL,
 full_name VARCHAR(120) NOT NULL, email VARCHAR(180) NOT NULL,
 stage ENUM('applied','screening','interview','offer','hired','rejected') NOT NULL DEFAULT 'applied',
 interview_at DATETIME NULL, notes TEXT NULL, created_by INT UNSIGNED NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY one_application(job_id,email), KEY job_stage(job_id,stage),
 FOREIGN KEY(job_id) REFERENCES job_openings(id), FOREIGN KEY(created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
