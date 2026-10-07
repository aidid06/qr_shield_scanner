<?php
// Run ONCE from the command line:  php migrate.php   (in Docker: docker exec <container> php migrate.php)
if (PHP_SAPI !== 'cli') { exit('Run this from the command line only.'); }
$db = new SQLite3(__DIR__ . '/database.sqlite');

$cols = [];
$r = $db->query('PRAGMA table_info(users)');
while ($c = $r->fetchArray(SQLITE3_ASSOC)) { $cols[] = $c['name']; }
foreach (['terms_version TEXT', 'terms_at DATETIME'] as $def) {
    $name = explode(' ', $def)[0];
    if (!in_array($name, $cols, true)) { $db->exec("ALTER TABLE users ADD COLUMN $def"); }
}
$db->exec("CREATE TABLE IF NOT EXISTS remember_tokens (
    selector   TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    user_id    INTEGER NOT NULL,
    expires    INTEGER NOT NULL
)");
echo "Migration done.\n";