<?php
class SQLiteAsMySQLResult {
    private $result;
    public function __construct($result) { $this->result = $result; }
    public function fetch_assoc() {
        return $this->result ? $this->result->fetchArray(SQLITE3_ASSOC) : null;
    }
    public function fetch_array($mode = SQLITE3_BOTH) {
        return $this->result ? $this->result->fetchArray($mode) : null;
    }
    public function num_rows() { return 0; }
}

class SQLiteAsMySQLConnection {
    private $sqlite;
    public $connect_error = null;

    public function __construct($db_file) {
        try {
            $is_new = !file_exists($db_file);
            $this->sqlite = new SQLite3($db_file);
            
            if ($is_new) {
                $this->initializeDatabase();
            }
        } catch (Exception $e) {
            $this->connect_error = $e->getMessage();
        }
    }

    private function initializeDatabase() {
        $this->sqlite->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                role TEXT DEFAULT 'user'
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scanned_url TEXT NOT NULL,
                scan_status TEXT NOT NULL,
                malicious_count INTEGER DEFAULT 0,
                total_engines INTEGER DEFAULT 0,
                scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        ");

        $this->sqlite->exec("
            INSERT OR IGNORE INTO users (id, username, email, password, created_at, role) 
            VALUES (1, 'Admin', 'admin@gmail.com', '\$2y\$10\$IvfIVMFzGYTNvjZhFyihUu8DreiTTLZ0LCRJ4XljVdc2n0kWtoQTq', '2026-08-03 12:54:10', 'admin');
            
            INSERT OR IGNORE INTO users (id, username, email, password, created_at, role) 
            VALUES (6, 'syakir', 'syakirzainor478@gmail.com', '\$2y\$10\$JhyB08mnLNtNfxA/ahxEfuXIkMWNB7SJw8B./Z4XcK7xCdBY5YdAi', '2026-08-16 08:00:39', 'user');
        ");
    }

    public function query($sql) {
        $res = $this->sqlite->query($sql);
        if ($res === false) return false;
        return new SQLiteAsMySQLResult($res);
    }

    public function prepare($sql) {
        return $this->sqlite->prepare($sql);
    }

    public function real_escape_string($string) {
        return SQLite3::escapeString($string);
    }

    public function insert_id() {
        return $this->sqlite->lastInsertRowID();
    }

    public function close() {
        return $this->sqlite->close();
    }
}

$db_file = __DIR__ . '/database.sqlite';
$conn = new SQLiteAsMySQLConnection($db_file);

if ($conn->connect_error) {
    die("Database Connection Failed: " . $conn->connect_error);
}
?>