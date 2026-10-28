<?php
// G0-D parity probe: canonical view of the effective PHP environment for one request.
$server = [];
foreach (['DOCUMENT_ROOT', 'SCRIPT_FILENAME', 'SCRIPT_NAME', 'PHP_SELF', 'REQUEST_URI', 'QUERY_STRING',
          'REQUEST_METHOD', 'HTTPS', 'SERVER_PORT', 'SERVER_NAME', 'HTTP_HOST', 'REMOTE_ADDR',
          'PATH_INFO', 'PATH_TRANSLATED', 'SERVER_PROTOCOL', 'REDIRECT_STATUS', 'GATEWAY_INTERFACE'] as $key) {
    $server[$key] = $_SERVER[$key] ?? null;
}
$ini = [];
foreach (ini_get_all(null, false) as $key => $value) {
    $ini[$key] = $value;
}
ksort($ini);
$extensions = get_loaded_extensions();
sort($extensions);
$zend = get_loaded_extensions(true);
sort($zend);
$user = function_exists('posix_geteuid') ? posix_getpwuid(posix_geteuid())['name'] : (string) getmyuid();
header('Content-Type: application/json');
echo json_encode([
    'sapi' => PHP_SAPI,
    'version' => PHP_VERSION,
    'ini_loaded' => php_ini_loaded_file(),
    'ini_scanned' => array_values(array_filter(array_map('trim', explode(',', (string) php_ini_scanned_files())))),
    'user' => $user,
    'umask' => sprintf('%04o', umask()),
    'cwd' => getcwd(),
    'tmp' => sys_get_temp_dir(),
    'extensions' => $extensions,
    'zend_extensions' => $zend,
    'ini' => $ini,
    'server' => $server,
], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), "\n";
