<?php
// TeamVault - PHP backend for login.html
// Handles register, login, logout and "who is signed in". Users are stored in data/users.json
//
// The browser never sends the real password. It sends a "login secret" made from the password
// (see js/crypto.js), and this file stores a hash of that secret.
// It also stores each user's public key and their private key (locked with the password).

const USERS_FILE = __DIR__ . '/data/users.json';

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
session_start();
header('Content-Type: application/json');

function reply(array $data): void {
    echo json_encode($data);
    exit;
}

function load_users(): array {
    if (!file_exists(USERS_FILE)) {
        return [];
    }
    $data = json_decode(file_get_contents(USERS_FILE), true);
    return is_array($data) ? $data : [];
}

function find_user(string $username): ?array {
    foreach (load_users() as $user) {
        if (strcasecmp($user['username'], $username) === 0) {
            return $user;
        }
    }
    return null;
}

// Returns 'ok', 'exists' or 'error'. The file is locked while writing.
function add_user(string $username, string $email, string $hash, string $publicKey, string $wrappedPrivateKey): string {
    $fp = fopen(USERS_FILE, 'c+');
    if ($fp === false) {
        return 'error';
    }
    flock($fp, LOCK_EX);
    $users = json_decode(stream_get_contents($fp), true);
    if (!is_array($users)) {
        $users = [];
    }
    foreach ($users as $u) {
        if (strcasecmp($u['username'], $username) === 0 || strcasecmp($u['email'], $email) === 0) {
            flock($fp, LOCK_UN);
            fclose($fp);
            return 'exists';
        }
    }
    $users[] = [
        'id'                  => count($users) + 1,
        'username'            => $username,
        'email'               => $email,
        'password'            => $hash,
        'public_key'          => $publicKey,
        'wrapped_private_key' => $wrappedPrivateKey,
        'created_at'          => date('c'),
    ];
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($users, JSON_PRETTY_PRINT));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return 'ok';
}

function text_of($value): string {
    return is_string($value) ? trim($value) : '';
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';

// Who is signed in
if ($action === 'me') {
    reply(['ok' => true, 'username' => $_SESSION['username'] ?? null]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    reply(['ok' => false, 'error' => 'Invalid request.']);
}

// Sign out
if ($action === 'logout') {
    $_SESSION = [];
    session_destroy();
    reply(['ok' => true]);
}

// Sign in
if ($action === 'login') {
    $username = text_of($_POST['username'] ?? '');
    $secret = text_of($_POST['password'] ?? '');
    $user = find_user($username);
    // Check a dummy hash when the user is not found, so timing does not reveal valid usernames
    $hash = $user['password'] ?? password_hash('dummy', PASSWORD_DEFAULT);

    if (password_verify($secret, $hash) && $user !== null) {
        session_regenerate_id(true);
        $_SESSION['username'] = $user['username'];
        reply([
            'ok'                  => true,
            'username'            => $user['username'],
            'wrapped_private_key' => $user['wrapped_private_key'] ?? '',
        ]);
    }
    reply(['ok' => false, 'error' => 'Incorrect username or password.']);
}

// Register
if ($action === 'register') {
    $username = text_of($_POST['username'] ?? '');
    $email = text_of($_POST['email'] ?? '');
    $secret = text_of($_POST['password'] ?? '');
    $publicKey = text_of($_POST['public_key'] ?? '');
    $wrappedPrivateKey = text_of($_POST['wrapped_private_key'] ?? '');

    if ($username === '' || mb_strlen($username) > 50) {
        reply(['ok' => false, 'error' => 'Username must be 1-50 characters.']);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        reply(['ok' => false, 'error' => 'Enter a valid email address.']);
    }
    // The password rules (at least 8 characters) are checked in the browser,
    // because the server only receives the login secret.
    if (!preg_match('/^[0-9a-f]{64}$/', $secret)) {
        reply(['ok' => false, 'error' => 'Invalid request.']);
    }
    if (strlen($publicKey) > 2000 || strlen($wrappedPrivateKey) > 10000
        || json_decode($publicKey) === null || json_decode($wrappedPrivateKey) === null) {
        reply(['ok' => false, 'error' => 'Invalid encryption keys.']);
    }

    $result = add_user($username, $email, password_hash($secret, PASSWORD_DEFAULT), $publicKey, $wrappedPrivateKey);
    if ($result === 'ok') {
        reply(['ok' => true]);
    }
    reply(['ok' => false, 'error' => $result === 'exists'
        ? 'That username or email is already registered.'
        : 'Could not save your account. Try again.']);
}

reply(['ok' => false, 'error' => 'Invalid request.']);
