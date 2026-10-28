<?php
$user = function_exists('posix_geteuid') ? posix_getpwuid(posix_geteuid())['name'] : (string) getmyuid();
echo json_encode(['sapi' => PHP_SAPI, 'version' => PHP_VERSION, 'user' => $user, 'ini' => php_ini_loaded_file()]), "\n";
