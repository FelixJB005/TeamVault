<?php
// TeamVault - PHP backend for main.html
//
// Everything is stored in data/communities.json, and encrypted files in data/files/.
//   community = { id, name, members: [{user, role}], channels: [channel] }
//   channel   = { id, name, type: 'general' or 'team', members: [usernames],
//                 keys: {username: lockedChannelKey}, messages: [], files: [] }
//
// This file never sees a readable message, file name, file or key: the browser encrypts them first.
// Roles: 'admin', 'subadmin' or 'member'.
//   Admin     - everything: change roles, add people, create and edit teams, read every team.
//   Sub-admin - add people (as members), create teams and edit the teams they are in.
//   Member    - chat and share files in the channels they can read.
// Everyone in a community can read the General channel.
// A team is readable by its chosen members, by all admins, and by the sub-admin who made it.

const USERS_FILE = __DIR__ . '/data/users.json';
const COMMUNITIES_FILE = __DIR__ . '/data/communities.json';
const FILES_DIR = __DIR__ . '/data/files';
const MAX_FILE_BYTES = 100 * 1024 * 1024 + 4096;   // 100 MB plus the small overhead of encryption
const ROLES = ['admin', 'subadmin', 'member'];

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
session_start();
header('Content-Type: application/json');

/* ---------- Small helpers ---------- */

function reply(array $data): void {
    echo json_encode($data);
    exit;
}

function fail(string $error): void {
    reply(['ok' => false, 'error' => $error]);
}

// Turn anything from the request into a trimmed string ('' if it is not text)
function text_of($value): string {
    return is_string($value) ? trim($value) : '';
}

function read_json(string $file): array {
    if (!file_exists($file)) {
        return [];
    }
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

// Everyone who has registered
function usernames(): array {
    return array_map(fn($user) => $user['username'], read_json(USERS_FILE));
}

// Open the communities file (locked), let $change edit it, then save it
function edit_communities(callable $change) {
    $fp = fopen(COMMUNITIES_FILE, 'c+');
    flock($fp, LOCK_EX);
    $all = json_decode(stream_get_contents($fp), true);
    if (!is_array($all)) {
        $all = [];
    }
    $result = $change($all);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($all, JSON_PRETTY_PRINT));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $result;
}

/* ---------- Community helpers ---------- */

function community_index(array $all, string $id): int {
    foreach ($all as $i => $c) {
        if ($c['id'] === $id) {
            return $i;
        }
    }
    return -1;
}

function channel_index(array $community, string $id): int {
    foreach ($community['channels'] as $i => $channel) {
        if ($channel['id'] === $id) {
            return $i;
        }
    }
    return -1;
}

function member_names(array $community): array {
    return array_map(fn($m) => $m['user'], $community['members']);
}

function member_role(array $community, string $user): ?string {
    foreach ($community['members'] as $m) {
        if ($m['user'] === $user) {
            return $m['role'];
        }
    }
    return null;
}

function admin_names(array $community): array {
    $admins = array_filter($community['members'], fn($m) => $m['role'] === 'admin');
    return array_values(array_map(fn($m) => $m['user'], $admins));
}

// Admins and sub-admins can add people and create teams
function can_manage(array $community, string $user): bool {
    return in_array(member_role($community, $user), ['admin', 'subadmin'], true);
}

// Read a JSON object {username: role} from the request
function clean_roles($value): array {
    $roles = is_string($value) ? json_decode($value, true) : null;
    return is_array($roles) ? $roles : [];
}

// Who can read a channel
function channel_members(array $community, array $channel): array {
    if ($channel['type'] === 'general') {
        return member_names($community);
    }
    return array_values(array_unique(array_merge($channel['members'], admin_names($community))));
}

// Index of a channel this user can read, or -1
function readable_channel(array $community, string $channelId, string $me): int {
    $k = channel_index($community, $channelId);
    if ($k >= 0 && in_array($me, channel_members($community, $community['channels'][$k]), true)) {
        return $k;
    }
    return -1;
}

// Read a JSON list of usernames from the request and keep only the allowed ones
function clean_names($value, array $allowed): array {
    $list = is_string($value) ? json_decode($value, true) : [];
    if (!is_array($list)) {
        return [];
    }
    return array_values(array_unique(array_intersect(array_filter($list, 'is_string'), $allowed)));
}

// Read a JSON object {name: lockedKey} and keep only allowed names with plausible key text
function clean_keys($value, array $allowed): array {
    $map = is_string($value) ? json_decode($value, true) : null;
    if (!is_array($map)) {
        return [];
    }
    $clean = [];
    foreach ($map as $name => $key) {
        if (in_array((string)$name, $allowed, true) && is_string($key)
            && strlen($key) <= 1000 && preg_match('/^[A-Za-z0-9+\/=]+$/', $key)) {
            $clean[$name] = $key;
        }
    }
    return $clean;
}

// Base64 text check for the encrypted parts sent by the browser
function is_b64($text, int $maxLength): bool {
    return is_string($text) && $text !== '' && strlen($text) <= $maxLength && preg_match('/^[A-Za-z0-9+\/=]+$/', $text) === 1;
}

// What the page gets to see: only the channels this user can read, without messages
function view_of(array $community, string $me): array {
    $channels = [];
    foreach ($community['channels'] as $channel) {
        $who = channel_members($community, $channel);
        if (in_array($me, $who, true)) {
            $channels[] = [
                'id'      => $channel['id'],
                'name'    => $channel['name'],
                'type'    => $channel['type'],
                'members' => $who,
                'key'     => $channel['keys'][$me] ?? '',   // the channel key locked for this user
                'desc_iv' => $channel['desc_iv'] ?? '',     // the team description, encrypted
                'desc_ct' => $channel['desc_ct'] ?? '',
            ];
        }
    }
    return [
        'id'       => $community['id'],
        'name'     => $community['name'],
        'role'     => member_role($community, $me),
        'members'  => $community['members'],
        'channels' => $channels,
    ];
}

/* ---------- Only signed in users can continue ---------- */

$me = $_SESSION['username'] ?? null;
if ($me === null) {
    http_response_code(401);
    reply(['ok' => false, 'error' => 'Please sign in.', 'signin' => true]);
}

// PHP throws away everything when an upload is bigger than post_max_size in php.ini
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && empty($_FILES) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
    fail('The upload is bigger than the server allows. Raise upload_max_filesize and post_max_size in php.ini.');
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';
$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';

/* ---------- Reading ---------- */

// Everyone who has registered, with their public key
if ($action === 'users') {
    $list = array_map(
        fn($u) => ['username' => $u['username'], 'public_key' => $u['public_key'] ?? ''],
        read_json(USERS_FILE)
    );
    usort($list, fn($a, $b) => strcasecmp($a['username'], $b['username']));
    reply(['ok' => true, 'users' => $list]);
}

// Communities that the signed in user belongs to
if ($action === 'communities') {
    $mine = [];
    foreach (read_json(COMMUNITIES_FILE) as $c) {
        if (member_role($c, $me) !== null) {
            $mine[] = view_of($c, $me);
        }
    }
    reply(['ok' => true, 'communities' => $mine]);
}

// Messages of one channel, only the ones newer than "after"
if ($action === 'messages') {
    $communityId = text_of($_GET['community'] ?? '');
    $channelId = text_of($_GET['channel'] ?? '');
    $after = (int)($_GET['after'] ?? 0);

    foreach (read_json(COMMUNITIES_FILE) as $c) {
        if ($c['id'] !== $communityId) {
            continue;
        }
        $k = readable_channel($c, $channelId, $me);
        if ($k >= 0) {
            $new = array_filter($c['channels'][$k]['messages'], fn($m) => $m['id'] > $after);
            reply(['ok' => true, 'messages' => array_values($new)]);
        }
    }
    fail('Chat not found.');
}

// The list of files in one channel (names are still encrypted)
if ($action === 'files') {
    $communityId = text_of($_GET['community'] ?? '');
    $channelId = text_of($_GET['channel'] ?? '');

    foreach (read_json(COMMUNITIES_FILE) as $c) {
        if ($c['id'] !== $communityId) {
            continue;
        }
        $k = readable_channel($c, $channelId, $me);
        if ($k >= 0) {
            reply(['ok' => true, 'files' => array_values($c['channels'][$k]['files'] ?? [])]);
        }
    }
    fail('Chat not found.');
}

// Download one encrypted file. The browser decrypts it.
if ($action === 'download_file') {
    $communityId = text_of($_GET['community'] ?? '');
    $channelId = text_of($_GET['channel'] ?? '');
    $fileId = text_of($_GET['file'] ?? '');
    $path = FILES_DIR . '/' . $fileId . '.enc';

    if (preg_match('/^[a-f0-9]{12}$/', $fileId) && file_exists($path)) {
        foreach (read_json(COMMUNITIES_FILE) as $c) {
            if ($c['id'] !== $communityId) {
                continue;
            }
            $k = readable_channel($c, $channelId, $me);
            if ($k < 0) {
                continue;
            }
            foreach ($c['channels'][$k]['files'] ?? [] as $f) {
                if ($f['id'] === $fileId) {
                    header('Content-Type: application/octet-stream');
                    header('Content-Length: ' . filesize($path));
                    readfile($path);
                    exit;
                }
            }
        }
    }
    fail('File not found.');
}

/* ---------- Writing ---------- */

// Create a community. The creator becomes its admin.
if ($action === 'create_community' && $isPost) {
    $name = text_of($_POST['name'] ?? '');
    if ($name === '' || mb_strlen($name) > 40) {
        fail('Community name must be 1-40 characters.');
    }

    // The creator is an admin. The people they add can be admins, sub-admins or members.
    $roles = clean_roles($_POST['roles'] ?? '');
    $members = [['user' => $me, 'role' => 'admin']];
    foreach (clean_names($_POST['members'] ?? '', usernames()) as $user) {
        if ($user !== $me) {
            $role = $roles[$user] ?? 'member';
            $members[] = ['user' => $user, 'role' => in_array($role, ROLES, true) ? $role : 'member'];
        }
    }

    // The browser sends the General channel key locked once for every member
    $names = array_map(fn($m) => $m['user'], $members);
    $keys = clean_keys($_POST['keys'] ?? '', $names);
    if (count($keys) !== count($names)) {
        fail('Encryption keys are missing.');
    }

    $community = [
        'id'         => bin2hex(random_bytes(6)),
        'name'       => $name,
        'members'    => $members,
        'channels'   => [['id' => 'general', 'name' => 'General', 'type' => 'general', 'members' => [], 'keys' => $keys, 'messages' => [], 'files' => []]],
        'created_at' => time(),
    ];
    edit_communities(function (array &$all) use ($community) {
        $all[] = $community;
    });
    reply(['ok' => true, 'community' => view_of($community, $me)]);
}

// Management actions: add people, change a role, create a team, edit a team
if ($isPost && in_array($action, ['add_members', 'set_role', 'create_team', 'update_team'], true)) {
    $communityId = text_of($_POST['community'] ?? '');

    $result = edit_communities(function (array &$all) use ($action, $me, $communityId) {
        $i = community_index($all, $communityId);
        if ($i < 0) {
            return ['error' => 'Community not found.'];
        }
        $c = &$all[$i];
        $myRole = member_role($c, $me);

        // Only admins change roles. Admins and sub-admins can do the rest.
        if ($action === 'set_role' ? $myRole !== 'admin' : !can_manage($c, $me)) {
            return ['error' => $action === 'set_role' ? 'Only admins can change roles.' : 'Only admins and sub-admins can do that.'];
        }

        // New people get the General channel key, locked for each of them.
        // Sub-admins can only add members. Admins can add members and sub-admins.
        // Making someone an admin is a separate step (set_role) because it needs the team keys.
        if ($action === 'add_members') {
            $new = array_values(array_diff(clean_names($_POST['members'] ?? '', usernames()), member_names($c)));
            $keys = clean_keys($_POST['keys'] ?? '', $new);
            if (count($keys) !== count($new)) {
                return ['error' => 'Encryption keys are missing.'];
            }
            $roles = clean_roles($_POST['roles'] ?? '');
            $g = channel_index($c, 'general');
            foreach ($new as $user) {
                $role = ($myRole === 'admin' && ($roles[$user] ?? '') === 'subadmin') ? 'subadmin' : 'member';
                $c['members'][] = ['user' => $user, 'role' => $role];
                $c['channels'][$g]['keys'][$user] = $keys[$user];
            }
            return ['error' => ''];
        }

        // A new admin gets the key of every team. Someone who stops being an admin loses
        // the keys of the teams they were not chosen for.
        if ($action === 'set_role') {
            $user = text_of($_POST['user'] ?? '');
            $role = text_of($_POST['role'] ?? '');
            $was = member_role($c, $user);
            if (!in_array($role, ROLES, true) || $was === null) {
                return ['error' => 'Invalid request.'];
            }
            if ($was === 'admin' && $role !== 'admin' && count(admin_names($c)) === 1) {
                return ['error' => 'A community needs at least one admin.'];
            }

            $keys = [];
            if ($role === 'admin') {
                $teamIds = [];
                foreach ($c['channels'] as $channel) {
                    if ($channel['type'] === 'team') {
                        $teamIds[] = $channel['id'];
                    }
                }
                $keys = clean_keys($_POST['keys'] ?? '', $teamIds);
                if (count($keys) !== count($teamIds)) {
                    return ['error' => 'Encryption keys are missing.'];
                }
            }

            foreach ($c['members'] as &$m) {
                if ($m['user'] === $user) {
                    $m['role'] = $role;
                }
            }
            unset($m);
            foreach ($c['channels'] as &$channel) {
                if ($channel['type'] !== 'team') {
                    continue;
                }
                if ($role === 'admin') {
                    $channel['keys'][$user] = $keys[$channel['id']];
                } elseif (!in_array($user, $channel['members'], true)) {
                    unset($channel['keys'][$user]);
                }
            }
            unset($channel);
            return ['error' => ''];
        }

        // create_team and update_team both need a name, a description, a list of members and the locked keys
        $name = text_of($_POST['name'] ?? '');
        if ($name === '' || mb_strlen($name) > 40) {
            return ['error' => 'Team name must be 1-40 characters.'];
        }

        // The description is encrypted in the browser (both parts are empty when there is no description)
        $descIv = text_of($_POST['desc_iv'] ?? '');
        $descCt = text_of($_POST['desc_ct'] ?? '');
        if (($descIv !== '' || $descCt !== '') && (strlen($descIv) !== 16 || !is_b64($descIv, 16) || !is_b64($descCt, 4000))) {
            return ['error' => 'Invalid description.'];
        }

        // A sub-admin is always part of the teams they create or edit
        $members = clean_names($_POST['members'] ?? '', member_names($c));
        if ($myRole === 'subadmin' && !in_array($me, $members, true)) {
            $members[] = $me;
        }
        $readers = array_values(array_unique(array_merge($members, admin_names($c))));
        $keys = clean_keys($_POST['keys'] ?? '', $readers);
        if (count($keys) !== count($readers)) {
            return ['error' => 'Encryption keys are missing.'];
        }

        if ($action === 'create_team') {
            $team = [
                'id' => bin2hex(random_bytes(6)), 'name' => $name, 'type' => 'team',
                'desc_iv' => $descIv, 'desc_ct' => $descCt,
                'members' => $members, 'keys' => $keys, 'messages' => [], 'files' => [],
            ];
            $c['channels'][] = $team;
            return ['error' => '', 'channel' => $team['id']];
        }

        // update_team: you can only edit a team you can read
        $channelId = text_of($_POST['channel'] ?? '');
        $k = readable_channel($c, $channelId, $me);
        if ($k < 0 || $c['channels'][$k]['type'] !== 'team') {
            return ['error' => 'Team not found.'];
        }
        $c['channels'][$k]['name'] = $name;
        $c['channels'][$k]['desc_iv'] = $descIv;
        $c['channels'][$k]['desc_ct'] = $descCt;
        $c['channels'][$k]['members'] = $members;
        $c['channels'][$k]['keys'] = $keys;
        return ['error' => '', 'channel' => $c['channels'][$k]['id']];
    });

    if ($result['error'] !== '') {
        fail($result['error']);
    }
    reply(['ok' => true, 'channel' => $result['channel'] ?? null]);
}

// Save an encrypted message (the browser sends iv and ct, which are unreadable here)
if ($action === 'send_message' && $isPost) {
    $communityId = text_of($_POST['community'] ?? '');
    $channelId = text_of($_POST['channel'] ?? '');
    $iv = text_of($_POST['iv'] ?? '');
    $ct = text_of($_POST['ct'] ?? '');
    if (!is_b64($iv, 16) || strlen($iv) !== 16 || !is_b64($ct, 8000)) {
        fail('Invalid message.');
    }

    $saved = edit_communities(function (array &$all) use ($me, $communityId, $channelId, $iv, $ct) {
        $i = community_index($all, $communityId);
        if ($i < 0) {
            return false;
        }
        $k = readable_channel($all[$i], $channelId, $me);
        if ($k < 0) {
            return false;
        }
        $all[$i]['channels'][$k]['messages'][] = [
            'id'   => count($all[$i]['channels'][$k]['messages']) + 1,
            'user' => $me,
            'at'   => time(),
            'iv'   => $iv,
            'ct'   => $ct,
        ];
        return true;
    });

    if (!$saved) {
        fail('Chat not found.');
    }
    reply(['ok' => true]);
}

// Save an encrypted file. The file name is encrypted too (name_iv, name_ct).
if ($action === 'upload_file' && $isPost) {
    $communityId = text_of($_POST['community'] ?? '');
    $channelId = text_of($_POST['channel'] ?? '');
    $iv = text_of($_POST['iv'] ?? '');
    $nameIv = text_of($_POST['name_iv'] ?? '');
    $nameCt = text_of($_POST['name_ct'] ?? '');
    // iv is the 8 byte start of the chunk IVs (12 characters). name_iv is a normal 12 byte IV (16 characters).
    if (strlen($iv) !== 12 || !is_b64($iv, 12) || strlen($nameIv) !== 16 || !is_b64($nameIv, 16) || !is_b64($nameCt, 2000)) {
        fail('Invalid file.');
    }

    $upload = $_FILES['blob'] ?? null;
    if (!$upload || $upload['error'] !== UPLOAD_ERR_OK) {
        fail('Upload failed. The file may be too large for the server.');
    }
    if ($upload['size'] > MAX_FILE_BYTES) {
        fail('Files can be at most 100 MB.');
    }

    // Check access before saving anything
    $allowed = false;
    foreach (read_json(COMMUNITIES_FILE) as $c) {
        if ($c['id'] === $communityId && readable_channel($c, $channelId, $me) >= 0) {
            $allowed = true;
        }
    }
    if (!$allowed) {
        fail('Chat not found.');
    }

    if (!is_dir(FILES_DIR)) {
        mkdir(FILES_DIR, 0775, true);
    }
    $fileId = bin2hex(random_bytes(6));
    $path = FILES_DIR . '/' . $fileId . '.enc';
    if (!move_uploaded_file($upload['tmp_name'], $path)) {
        fail('Could not save the file.');
    }

    $size = $upload['size'];
    $saved = edit_communities(function (array &$all) use ($me, $communityId, $channelId, $fileId, $iv, $nameIv, $nameCt, $size) {
        $i = community_index($all, $communityId);
        $k = $i < 0 ? -1 : readable_channel($all[$i], $channelId, $me);
        if ($k < 0) {
            return false;
        }
        $all[$i]['channels'][$k]['files'][] = [
            'id'      => $fileId,
            'user'    => $me,
            'at'      => time(),
            'iv'      => $iv,
            'name_iv' => $nameIv,
            'name_ct' => $nameCt,
            'size'    => $size,
        ];
        return true;
    });

    if (!$saved) {
        unlink($path);
        fail('Chat not found.');
    }
    reply(['ok' => true]);
}

// Delete a file. Only the person who uploaded it, an admin or a sub-admin can do this.
if ($action === 'delete_file' && $isPost) {
    $communityId = text_of($_POST['community'] ?? '');
    $channelId = text_of($_POST['channel'] ?? '');
    $fileId = text_of($_POST['file'] ?? '');

    $deleted = edit_communities(function (array &$all) use ($me, $communityId, $channelId, $fileId) {
        $i = community_index($all, $communityId);
        $k = $i < 0 ? -1 : readable_channel($all[$i], $channelId, $me);
        if ($k < 0) {
            return false;
        }
        foreach ($all[$i]['channels'][$k]['files'] as $n => $f) {
            if ($f['id'] === $fileId) {
                if ($f['user'] !== $me && !can_manage($all[$i], $me)) {
                    return false;
                }
                array_splice($all[$i]['channels'][$k]['files'], $n, 1);
                return true;
            }
        }
        return false;
    });

    if (!$deleted) {
        fail('Could not delete the file.');
    }
    if (preg_match('/^[a-f0-9]{12}$/', $fileId) && file_exists(FILES_DIR . '/' . $fileId . '.enc')) {
        unlink(FILES_DIR . '/' . $fileId . '.enc');
    }
    reply(['ok' => true]);
}

fail('Invalid request.');
