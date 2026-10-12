// TeamVault main page: communities, teams, encrypted chat and encrypted files.
// Uses auth.php (who is signed in), api.php (the data) and crypto.js (encryption).
// Messages, descriptions, file names and files are encrypted here in the browser before they are sent,
// so the server only ever stores unreadable data.

const COLORS = ['#16a34a', '#0d9488', '#2563eb', '#7c3aed', '#db2777', '#ea580c'];
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const FILE_TYPES = {
  txt: 'text/plain',
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};
const ROLE_LABELS = { admin: 'Admin', subadmin: 'Sub-admin', member: 'Member' };

let me = '';                    // username of the signed in user
let privateKey = null;          // your private key, used to unlock channel keys
const publicKeys = {};          // username -> public key, used to lock keys for other people
const keyCache = new Map();     // locked channel key -> unlocked channel key
let people = [];                // usernames of everyone registered
let communities = [];           // communities this user belongs to
let currentCommunityId = null;  // community that is open
let currentChannelId = null;    // channel that is open: 'general' or a team id
let currentTab = 'chat';        // 'chat', 'files' or 'members'
let lastMessageId = 0;          // newest message shown in the open channel
let filesSignature = '';        // used to redraw the file list only when it changed
let loadingMessages = false;
let editingTeam = null;         // the team being edited in the team dialog (null when creating)

// Settings are saved in this browser
const settings = {
  color: localStorage.getItem('tv_color') || COLORS[0],
  compact: localStorage.getItem('tv_compact') === '1',
};

const $ = (id) => document.getElementById(id);

/* ---------- Small helpers ---------- */

// Create an element. Using textContent keeps user text safe.
function make(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Initials for the profile picture: "Felix Joy" -> "FJ", "felix" -> "F"
function initials(name) {
  const parts = name.trim().split(/[\s._-]+/).filter(Boolean);
  const first = (word) => Array.from(word)[0];
  const letters = parts.length > 1 ? first(parts[0]) + first(parts[1]) : first(parts[0] || '?');
  return letters.toUpperCase();
}

// The same text always gives the same color
function hashColor(text) {
  let sum = 0;
  for (const ch of text) sum += ch.codePointAt(0);
  return COLORS[sum % COLORS.length];
}

// You get the color from Settings, everyone else gets one based on their name
function colorFor(name) {
  return name === me ? settings.color : hashColor(name);
}

function makeAvatar(name, extraClass) {
  const avatar = make('span', 'avatar ' + extraClass, initials(name));
  avatar.dataset.name = name;
  avatar.style.background = colorFor(name);
  return avatar;
}

// Recolor every avatar on the page (after a Settings change)
function refreshAvatars() {
  document.querySelectorAll('.avatar[data-name]').forEach((avatar) => {
    avatar.style.background = colorFor(avatar.dataset.name);
  });
}

function makeBadge(role) {
  const className = role === 'admin' ? 'badge' : role === 'subadmin' ? 'badge sub' : 'badge plain';
  return make('span', className, ROLE_LABELS[role] || 'Member');
}

function formatTime(seconds) {
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDate(seconds) {
  return new Date(seconds * 1000).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// Talk to api.php. Returns the JSON reply.
async function api(action, data = {}, post = false) {
  const params = new URLSearchParams({ action, ...data });
  try {
    const response = post
      ? await fetch('api.php', { method: 'POST', body: params })
      : await fetch('api.php?' + params);
    const result = await response.json();
    if (result.signin) window.location.href = 'login.html';
    return result;
  } catch (error) {
    return { ok: false, error: 'Could not reach the server.' };
  }
}

/* ---------- Encryption keys ---------- */

// The unlocked key of a channel. Only people who have a copy of it can read the channel.
async function keyOf(channel) {
  if (!channel || !channel.key) return null;
  if (!keyCache.has(channel.key)) {
    keyCache.set(channel.key, await TVCrypto.unwrapKey(channel.key, privateKey));
  }
  return keyCache.get(channel.key);
}

// Lock a channel key once for each person in the list, using their public keys
async function wrapFor(channelKey, names) {
  const locked = {};
  for (const name of names) {
    if (!publicKeys[name]) throw new Error(name + ' has no encryption key yet.');
    locked[name] = await TVCrypto.wrapKey(channelKey, publicKeys[name]);
  }
  return locked;
}

// The team description is encrypted with the team key
async function descriptionOf(channel) {
  if (!channel || !channel.desc_ct) return '';
  try {
    const key = await keyOf(channel);
    return key ? await TVCrypto.decryptText(key, channel.desc_iv, channel.desc_ct) : '';
  } catch (error) {
    return '';
  }
}

// A new admin needs a copy of every team key, so the admin who promotes them locks those keys for them
async function keysForNewAdmin(user) {
  const keys = {};
  for (const channel of currentCommunity().channels) {
    if (channel.type !== 'team') continue;
    const key = await keyOf(channel);
    if (!key || !publicKeys[user]) throw new Error('Could not prepare the encryption keys.');
    keys[channel.id] = await TVCrypto.wrapKey(key, publicKeys[user]);
  }
  return keys;
}

/* ---------- What is open right now, and what you are allowed to do ---------- */

function currentCommunity() {
  return communities.find((c) => c.id === currentCommunityId);
}

function currentChannel() {
  const community = currentCommunity();
  return community && community.channels.find((ch) => ch.id === currentChannelId);
}

function myRole() {
  const community = currentCommunity();
  return community ? community.role : '';
}

// Admins change roles. Admins and sub-admins add people and create teams.
const isAdmin = () => myRole() === 'admin';
const canManage = () => myRole() === 'admin' || myRole() === 'subadmin';

/* ---------- Dropdown menus ---------- */

function closeMenus() {
  document.querySelectorAll('.menu').forEach((menu) => { menu.hidden = true; });
  document.querySelectorAll('[aria-expanded]').forEach((button) => button.setAttribute('aria-expanded', 'false'));
}

function setupMenu(buttonId, menuId) {
  $(buttonId).addEventListener('click', (event) => {
    event.stopPropagation();
    const open = $(menuId).hidden;
    closeMenus();
    $(menuId).hidden = !open;
    $(buttonId).setAttribute('aria-expanded', open);
  });
}

document.addEventListener('click', closeMenus);
setupMenu('profileButton', 'profileMenu');
setupMenu('chatMenuButton', 'chatMenu');

/* ---------- Sidebar ---------- */

function renderCommunities() {
  const list = $('communityList');
  list.replaceChildren();
  if (communities.length === 0) {
    list.append(make('li', 'hint', 'No communities yet'));
  }
  for (const community of communities) {
    const icon = make('span', 'group-icon', initials(community.name));
    icon.style.background = hashColor(community.name);

    const button = make('button', 'item' + (community.id === currentCommunityId ? ' active' : ''));
    button.type = 'button';
    button.append(icon, make('span', 'item-name', community.name));
    button.addEventListener('click', () => openChannel(community.id, 'general'));

    const row = make('li');
    row.append(button);
    list.append(row);
  }
}

function channelRow(channel) {
  const button = make('button', 'item' + (channel.id === currentChannelId ? ' active' : ''));
  button.type = 'button';
  button.append(make('span', 'hash', channel.type === 'general' ? '#' : '\u25C6'), make('span', 'item-name', channel.name));
  button.addEventListener('click', () => openChannel(currentCommunityId, channel.id, true));
  const row = make('li');
  row.append(button);
  return row;
}

function renderChannels() {
  const community = currentCommunity();
  $('channelList').replaceChildren();
  $('teamList').replaceChildren();
  for (const channel of community.channels) {
    const list = channel.type === 'general' ? $('channelList') : $('teamList');
    list.append(channelRow(channel));
  }
  if ($('teamList').children.length === 0) {
    $('teamList').append(make('li', 'hint', canManage() ? 'No teams yet. Use + to create one.' : 'You are not in a team yet.'));
  }

  $('communityInfo').replaceChildren(make('strong', '', community.name), makeBadge(community.role));
}

/* ---------- Showing a community and its channel ---------- */

function showEmpty() {
  $('emptyState').hidden = false;
  $('workspace').hidden = true;
  $('navTabs').hidden = true;
  $('communityPanel').hidden = true;
  renderCommunities();
}

// The description of a team is encrypted, so it is decrypted here and shown under the title
async function showDescription() {
  const openId = currentChannelId;
  const text = await descriptionOf(currentChannel());
  if (openId !== currentChannelId) return;
  $('chatDescription').textContent = text;
  $('chatDescription').hidden = !text;
}

// Redraw the sidebar, the page header and the buttons for what is open
function showCommunity() {
  const community = currentCommunity();
  const channel = currentChannel();
  const manage = canManage();

  $('emptyState').hidden = true;
  $('workspace').hidden = false;
  $('navTabs').hidden = false;
  $('communityPanel').hidden = false;
  renderCommunities();
  renderChannels();

  const count = channel.members.length;
  $('chatTitle').textContent = (channel.type === 'general' ? '# ' : '\u25C6 ') + channel.name;
  $('chatSub').textContent = community.name + ' \u00B7 ' + count + (count === 1 ? ' person' : ' people');
  $('chatSub').title = channel.members.join(', ');
  showDescription();

  // Only admins and sub-admins see the management buttons
  $('chatMenuButton').hidden = !manage;
  $('menuAddPeople').hidden = !manage;
  $('menuNewTeam').hidden = !manage;
  $('menuEditTeam').hidden = !(manage && channel.type === 'team');
  $('sideNewTeam').hidden = !manage;
  $('addPeople').hidden = !manage;
  $('newTeam').hidden = !manage;

  if (currentTab === 'members') drawMembersPane();
}

// After the lists changed: keep what is open, or pick something that still exists
function refreshView() {
  const community = currentCommunity();
  if (!community) {
    if (communities.length > 0) openChannel(communities[0].id, 'general');
    else showEmpty();
  } else if (!currentChannel()) {
    openChannel(community.id, 'general');
  } else {
    showCommunity();
  }
}

// toChat: also go to the Chat tab (used when you click a channel in the sidebar)
async function openChannel(communityId, channelId, toChat = false) {
  const same = communityId === currentCommunityId && channelId === currentChannelId;
  if (!same) {
    currentCommunityId = communityId;
    currentChannelId = channelId;
    lastMessageId = 0;
    filesSignature = '';
    $('messages').querySelectorAll('.message').forEach((node) => node.remove());
    $('noMessages').hidden = false;
    $('fileList').replaceChildren();
    showCommunity();
  }
  if (toChat) showTab('chat');
  if (!same) {
    await loadMessages();
    if (currentTab === 'files') loadFiles();
  }
  if (currentTab === 'chat') $('messageInput').focus();
}

async function loadPeople() {
  const data = await api('users');
  if (!data.ok) return;
  people = data.users.map((user) => user.username);
  for (const user of data.users) publicKeys[user.username] = user.public_key;
}

async function loadCommunities() {
  const data = await api('communities');
  if (!data.ok) return;
  // Only redraw when something changed
  if (JSON.stringify(data.communities) === JSON.stringify(communities)) return;
  communities = data.communities;
  refreshView();
}

/* ---------- Tabs in the top bar ---------- */

function showTab(name) {
  currentTab = name;
  $('chatPane').hidden = name !== 'chat';
  $('filesPane').hidden = name !== 'files';
  $('membersPane').hidden = name !== 'members';
  $('channelHead').hidden = name === 'members';
  $('tabChat').classList.toggle('active', name === 'chat');
  $('tabFiles').classList.toggle('active', name === 'files');
  $('tabMembers').classList.toggle('active', name === 'members');
  if (name === 'files') loadFiles();
  if (name === 'members') drawMembersPane();
}

$('tabChat').addEventListener('click', () => showTab('chat'));
$('tabFiles').addEventListener('click', () => showTab('files'));
$('tabMembers').addEventListener('click', () => showTab('members'));

/* ---------- Chat ---------- */

function makeMessage(message, text) {
  const mine = message.user === me;
  const meta = make('div', 'meta');
  meta.append(make('strong', '', mine ? 'You' : message.user), make('time', '', formatTime(message.at)));

  const bubble = make('div', 'bubble');
  bubble.append(meta, make('p', '', text));

  const row = make('div', 'message' + (mine ? ' mine' : ''));
  row.append(makeAvatar(message.user, 'small'), bubble);
  return row;
}

// Decrypt one message. Shows a notice instead of text if it cannot be decrypted.
async function readMessage(key, message) {
  if (!key) return '[You do not have the key for this chat]';
  try {
    return await TVCrypto.decryptText(key, message.iv, message.ct);
  } catch (error) {
    return '[This message could not be decrypted]';
  }
}

// Fetch messages newer than the last one shown, decrypt them and add them to the page
async function loadMessages() {
  if (!currentChannelId || loadingMessages) return;
  loadingMessages = true;
  const communityId = currentCommunityId;
  const channelId = currentChannelId;
  const data = await api('messages', { community: communityId, channel: channelId, after: lastMessageId });
  loadingMessages = false;

  // Ignore the reply if something else was opened meanwhile
  if (!data.ok || communityId !== currentCommunityId || channelId !== currentChannelId) return;

  let key = null;
  try {
    key = await keyOf(currentChannel());
  } catch (error) {}

  const box = $('messages');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  for (const message of data.messages) {
    const text = await readMessage(key, message);
    if (communityId !== currentCommunityId || channelId !== currentChannelId) return;
    box.append(makeMessage(message, text));
    lastMessageId = message.id;
  }
  $('noMessages').hidden = lastMessageId > 0;
  if (data.messages.length > 0 && (nearBottom || data.messages.some((m) => m.user === me))) {
    box.scrollTop = box.scrollHeight;
  }
}

$('messageForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = $('messageInput');
  const text = input.value.trim();
  if (!text || !currentChannelId) return;

  input.value = '';
  try {
    const key = await keyOf(currentChannel());
    if (!key) throw new Error('You do not have the key for this chat.');
    const encrypted = await TVCrypto.encryptText(key, text);
    const data = await api('send_message', {
      community: currentCommunityId,
      channel: currentChannelId,
      iv: encrypted.iv,
      ct: encrypted.ct,
    }, true);
    if (!data.ok) throw new Error(data.error);
    loadMessages();
  } catch (error) {
    input.value = text;
    alert(error.message);
  }
});

/* ---------- Encrypted files ---------- */

function fileExtension(name) {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
}

// Only .txt, .pdf and .docx files up to 100 MB. The server cannot see file names or contents
// (they are encrypted), so these checks are made here. Returns a problem text, or '' if the file is fine.
async function checkFile(file) {
  const ext = fileExtension(file.name);
  if (!FILE_TYPES[ext]) return 'Only .txt, .pdf and .docx files are allowed.';
  if (file.size === 0) return 'The file is empty.';
  if (file.size > MAX_FILE_BYTES) return 'Files can be at most 100 MB.';

  // Make sure the content really matches the extension
  const head = new Uint8Array(await file.slice(0, 1024).arrayBuffer());
  const asText = new TextDecoder('latin1').decode(head);
  if (ext === 'pdf' && !asText.includes('%PDF-')) return 'This is not a real PDF file.';
  if (ext === 'docx' && !(head[0] === 0x50 && head[1] === 0x4b && head[2] === 3 && head[3] === 4)) return 'This is not a real Word (.docx) file.';
  const hasBom = (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff);
  if (ext === 'txt' && !hasBom && head.includes(0)) return 'This is not a plain text file.';
  return '';
}

function renderFiles(files) {
  const list = $('fileList');
  list.replaceChildren();
  if (files.length === 0) {
    list.append(make('p', 'hint', 'No files yet. Upload one and it is encrypted in your browser first.'));
  }
  for (const file of files) {
    const info = make('div', 'file-info');
    info.append(
      make('div', 'file-name', file.name),
      make('div', 'file-meta', formatSize(file.size) + ' \u00B7 ' + (file.user === me ? 'you' : file.user) + ' \u00B7 ' + formatDate(file.at))
    );

    const actions = make('div', 'file-actions');
    const download = make('button', 'secondary', 'Download');
    download.type = 'button';
    download.addEventListener('click', () => downloadFile(file, download));
    actions.append(download);

    if (file.user === me || canManage()) {
      const remove = make('button', 'secondary', 'Delete');
      remove.type = 'button';
      remove.addEventListener('click', () => deleteFile(file));
      actions.append(remove);
    }

    const ext = fileExtension(file.name);
    const row = make('div', 'file-row');
    row.append(make('div', 'file-icon', ext ? ext.slice(0, 4).toUpperCase() : 'FILE'), info, actions);
    list.append(row);
  }
}

// Get the list of files and decrypt their names
async function loadFiles() {
  if (!currentChannelId) return;
  const communityId = currentCommunityId;
  const channelId = currentChannelId;
  const data = await api('files', { community: communityId, channel: channelId });
  if (!data.ok || communityId !== currentCommunityId || channelId !== currentChannelId) return;

  // Only redraw when something changed
  const signature = JSON.stringify(data.files.map((f) => f.id));
  if (signature === filesSignature) return;
  filesSignature = signature;

  let key = null;
  try {
    key = await keyOf(currentChannel());
  } catch (error) {}

  const files = [];
  for (const file of data.files) {
    let info = { name: '(unreadable file name)', type: '', size: file.size };
    if (key) {
      try {
        info = { ...info, ...JSON.parse(await TVCrypto.decryptText(key, file.name_iv, file.name_ct)) };
      } catch (error) {}
    }
    files.push({ ...file, name: info.name, type: info.type, size: info.size });
  }
  if (communityId !== currentCommunityId || channelId !== currentChannelId) return;
  renderFiles(files);
}

// Upload with a progress percentage (fetch cannot report upload progress)
function sendForm(form, onProgress) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', 'api.php');
    request.responseType = 'json';
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onload = () => resolve(request.response || { ok: false, error: 'The server did not accept the upload.' });
    request.onerror = () => reject(new Error('Could not reach the server.'));
    request.send(form);
  });
}

async function uploadFile(file) {
  const problem = await checkFile(file);
  if (problem) {
    alert(file.name + ': ' + problem);
    return;
  }
  const status = $('uploadStatus');
  try {
    const key = await keyOf(currentChannel());
    if (!key) throw new Error('You do not have the key for this chat.');

    // Encrypt the file and its name here, then upload only the encrypted data
    status.textContent = 'Encrypting ' + file.name + '...';
    const encryptedFile = await TVCrypto.encryptFile(key, file);
    const meta = { name: file.name, type: FILE_TYPES[fileExtension(file.name)], size: file.size };
    const encryptedName = await TVCrypto.encryptText(key, JSON.stringify(meta));

    const form = new FormData();
    form.append('action', 'upload_file');
    form.append('community', currentCommunityId);
    form.append('channel', currentChannelId);
    form.append('iv', encryptedFile.iv);
    form.append('name_iv', encryptedName.iv);
    form.append('name_ct', encryptedName.ct);
    form.append('blob', encryptedFile.blob, 'file.enc');

    const data = await sendForm(form, (percent) => { status.textContent = 'Uploading ' + file.name + '... ' + percent + '%'; });
    if (!data.ok) throw new Error(data.error);
  } catch (error) {
    alert('Could not upload ' + file.name + ': ' + error.message);
  } finally {
    status.textContent = '';
  }
}

$('fileInput').addEventListener('change', async (event) => {
  const picked = [...event.target.files];
  event.target.value = '';
  for (const file of picked) await uploadFile(file);
  filesSignature = '';
  loadFiles();
});

async function downloadFile(file, button) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Decrypting...';
  try {
    const key = await keyOf(currentChannel());
    if (!key) throw new Error('You do not have the key for this chat.');

    const params = new URLSearchParams({ action: 'download_file', community: currentCommunityId, channel: currentChannelId, file: file.id });
    const response = await fetch('api.php?' + params);
    if ((response.headers.get('content-type') || '').includes('json')) {
      throw new Error((await response.json()).error);
    }

    // Decrypt in the browser, then save the readable file
    const plain = await TVCrypto.decryptFile(key, file.iv, await response.arrayBuffer());
    const url = URL.createObjectURL(plain.slice(0, plain.size, file.type || 'application/octet-stream'));
    const link = make('a');
    link.href = url;
    link.download = file.name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (error) {
    alert('Could not download ' + file.name + ': ' + error.message);
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

async function deleteFile(file) {
  if (!confirm('Delete ' + file.name + '?')) return;
  const data = await api('delete_file', { community: currentCommunityId, channel: currentChannelId, file: file.id }, true);
  if (!data.ok) {
    alert(data.error);
    return;
  }
  filesSignature = '';
  loadFiles();
}

/* ---------- Dialogs: lists of people with checkboxes (and a role for each) ---------- */

// roles: a list like ['member', 'subadmin'] shows a role menu next to each person, or null for no menu
function fillChecklist(box, names, checked, emptyText, roles) {
  box.replaceChildren();
  if (names.length === 0) box.append(make('p', 'hint', emptyText));
  for (const name of names) {
    const checkbox = make('input');
    checkbox.type = 'checkbox';
    checkbox.value = name;
    checkbox.checked = checked.includes(name);
    const label = make('label', 'check');
    label.append(checkbox, makeAvatar(name, 'small'), make('span', 'item-name', name));

    const row = make('div', 'check-row');
    row.append(label);
    if (roles) {
      const select = make('select');
      select.setAttribute('aria-label', 'Role of ' + name);
      for (const role of roles) {
        const option = make('option', '', ROLE_LABELS[role]);
        option.value = role;
        select.append(option);
      }
      row.append(select);
    }
    box.append(row);
  }
}

// The people that are ticked, with the role chosen for each: [{ name, role }]
function checkedPeople(box) {
  return [...box.querySelectorAll('.check-row')]
    .filter((row) => row.querySelector('input').checked)
    .map((row) => ({
      name: row.querySelector('input').value,
      role: row.querySelector('select') ? row.querySelector('select').value : 'member',
    }));
}

const rolesObject = (list) => Object.fromEntries(list.map((p) => [p.name, p.role]));

/* ---------- Create a community ---------- */

function openCreateDialog() {
  $('communityName').value = '';
  $('createError').textContent = '';
  const others = people.filter((name) => name !== me);
  fillChecklist($('memberChoices'), others, [], 'Nobody else has registered yet.', ['member', 'subadmin', 'admin']);
  $('createDialog').showModal();
  $('communityName').focus();
}

$('newCommunity').addEventListener('click', openCreateDialog);
$('emptyCreate').addEventListener('click', openCreateDialog);
$('cancelCreate').addEventListener('click', () => $('createDialog').close());

$('createForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('communityName').value.trim();
  if (!name) {
    $('createError').textContent = 'Enter a community name.';
    return;
  }
  const chosen = checkedPeople($('memberChoices'));
  const names = chosen.map((p) => p.name);

  let keys;
  try {
    // A new key for the General channel, locked once for you and once for each person you add
    const generalKey = await TVCrypto.newChannelKey();
    keys = await wrapFor(generalKey, [me, ...names]);
  } catch (error) {
    $('createError').textContent = error.message;
    return;
  }

  const data = await api('create_community', {
    name,
    members: JSON.stringify(names),
    roles: JSON.stringify(rolesObject(chosen)),
    keys: JSON.stringify(keys),
  }, true);
  if (!data.ok) {
    $('createError').textContent = data.error;
    return;
  }
  $('createDialog').close();
  await loadCommunities();
  openChannel(data.community.id, 'general', true);
});

/* ---------- Add people to the open community ---------- */

function openAddDialog() {
  $('addError').textContent = '';
  const inside = currentCommunity().members.map((m) => m.user);
  const outside = people.filter((name) => !inside.includes(name));

  // Admins can add members, sub-admins and admins. Sub-admins can only add members.
  const roles = isAdmin() ? ['member', 'subadmin', 'admin'] : null;
  $('addNote').textContent = isAdmin() ? 'Choose a role for each person.' : 'People you add join as members.';
  fillChecklist($('addChoices'), outside, [], 'Everyone who has registered is already in this community.', roles);
  $('addDialog').showModal();
}

$('addPeople').addEventListener('click', openAddDialog);
$('menuAddPeople').addEventListener('click', openAddDialog);
$('cancelAdd').addEventListener('click', () => $('addDialog').close());

$('addForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const chosen = checkedPeople($('addChoices'));
  const names = chosen.map((p) => p.name);

  let keys;
  try {
    // Give the new people a copy of the General channel key
    const general = currentCommunity().channels.find((c) => c.type === 'general');
    const generalKey = await keyOf(general);
    if (!generalKey) throw new Error('You do not have the key for this community.');
    keys = await wrapFor(generalKey, names);
  } catch (error) {
    $('addError').textContent = error.message;
    return;
  }

  // People who should be admins are added as members first, then promoted (that step needs the team keys)
  const firstRoles = Object.fromEntries(chosen.map((p) => [p.name, p.role === 'admin' ? 'member' : p.role]));
  const data = await api('add_members', {
    community: currentCommunityId,
    members: JSON.stringify(names),
    roles: JSON.stringify(firstRoles),
    keys: JSON.stringify(keys),
  }, true);
  if (!data.ok) {
    $('addError').textContent = data.error;
    return;
  }

  for (const person of chosen.filter((p) => p.role === 'admin')) {
    try {
      const teamKeys = await keysForNewAdmin(person.name);
      const result = await api('set_role', { community: currentCommunityId, user: person.name, role: 'admin', keys: JSON.stringify(teamKeys) }, true);
      if (!result.ok) throw new Error(result.error);
    } catch (error) {
      alert(person.name + ' was added, but could not be made an admin: ' + error.message);
    }
  }
  $('addDialog').close();
  loadCommunities();
});

/* ---------- Create or edit a team ---------- */

// Pass a team (channel) to edit it, or nothing to create a new team
async function openTeamDialog(team) {
  editingTeam = team || null;
  $('teamTitle').textContent = team ? 'Edit team' : 'New team';
  $('teamName').value = team ? team.name : '';
  $('teamDescription').value = team ? await descriptionOf(team) : '';
  $('teamError').textContent = '';

  // Admins can always read every team, and a sub-admin stays in the teams they create or edit,
  // so those people are not listed
  const community = currentCommunity();
  const listed = community.members.filter((m) => m.role !== 'admin' && m.user !== me).map((m) => m.user);
  fillChecklist($('teamChoices'), listed, team ? team.members : [], 'Add people to the community first.', null);
  $('teamNote').textContent = isAdmin()
    ? 'Admins can always read every team.'
    : 'Admins can always read every team, and you are always part of the teams you create or edit.';

  $('teamDialog').showModal();
  $('teamName').focus();
}

$('newTeam').addEventListener('click', () => openTeamDialog(null));
$('sideNewTeam').addEventListener('click', () => openTeamDialog(null));
$('menuNewTeam').addEventListener('click', () => openTeamDialog(null));
$('menuEditTeam').addEventListener('click', () => openTeamDialog(currentChannel()));
$('cancelTeam').addEventListener('click', () => $('teamDialog').close());

$('teamForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('teamName').value.trim();
  if (!name) {
    $('teamError').textContent = 'Enter a team name.';
    return;
  }
  const description = $('teamDescription').value.trim();

  // Everyone who can read the team: the people ticked, every admin, and you
  const chosen = checkedPeople($('teamChoices')).map((p) => p.name);
  const admins = currentCommunity().members.filter((m) => m.role === 'admin').map((m) => m.user);
  const readers = [...new Set([...chosen, ...admins, me])];

  let fields;
  try {
    // A new team gets a new key. An existing team keeps its key and it is locked again for the new list of readers.
    const teamKey = editingTeam ? await keyOf(editingTeam) : await TVCrypto.newChannelKey();
    if (!teamKey) throw new Error('You do not have the key for this team.');
    const encrypted = description ? await TVCrypto.encryptText(teamKey, description) : { iv: '', ct: '' };
    fields = {
      community: currentCommunityId,
      name,
      members: JSON.stringify(chosen),
      desc_iv: encrypted.iv,
      desc_ct: encrypted.ct,
      keys: JSON.stringify(await wrapFor(teamKey, readers)),
    };
  } catch (error) {
    $('teamError').textContent = error.message;
    return;
  }
  if (editingTeam) fields.channel = editingTeam.id;

  const data = await api(editingTeam ? 'update_team' : 'create_team', fields, true);
  if (!data.ok) {
    $('teamError').textContent = data.error;
    return;
  }
  const wasEditing = Boolean(editingTeam);
  $('teamDialog').close();
  await loadCommunities();
  openChannel(currentCommunityId, data.channel, !wasEditing);
});

/* ---------- Members tab ---------- */

function makeMemberCard(member) {
  const info = make('div', 'card-info');
  info.append(make('div', 'card-name', member.user + (member.user === me ? ' (you)' : '')));

  const card = make('div', 'card');
  card.append(makeAvatar(member.user, ''), info);

  if (isAdmin()) {
    // Admins can change anyone's role
    const select = make('select');
    select.setAttribute('aria-label', 'Role of ' + member.user);
    for (const role of ['member', 'subadmin', 'admin']) {
      const option = make('option', '', ROLE_LABELS[role]);
      option.value = role;
      option.selected = member.role === role;
      select.append(option);
    }
    select.addEventListener('change', () => changeRole(member.user, select.value));
    card.append(select);
  } else {
    card.append(makeBadge(member.role));
  }
  return card;
}

async function changeRole(user, role) {
  const fields = { community: currentCommunityId, user, role };
  try {
    if (role === 'admin') fields.keys = JSON.stringify(await keysForNewAdmin(user));
  } catch (error) {
    alert(error.message);
    drawMembersPane();
    return;
  }
  const data = await api('set_role', fields, true);
  if (!data.ok) alert(data.error);
  await loadCommunities();
  drawMembersPane();
}

function makeTeamCard(team, description) {
  const info = make('div', 'card-info');
  info.append(make('div', 'card-name', team.name));
  if (description) info.append(make('div', 'card-sub', description));

  const stack = make('div', 'avatar-stack');
  for (const name of team.members.slice(0, 6)) stack.append(makeAvatar(name, 'small'));
  const extra = team.members.length - 6;
  info.append(stack, make('div', 'card-sub', team.members.length + (team.members.length === 1 ? ' person' : ' people') + (extra > 0 ? ' (+' + extra + ' not shown)' : '')));

  const actions = make('div', 'file-actions');
  const open = make('button', 'secondary', 'Open');
  open.type = 'button';
  open.addEventListener('click', () => openChannel(currentCommunityId, team.id, true));
  actions.append(open);
  if (canManage()) {
    const edit = make('button', 'secondary', 'Edit');
    edit.type = 'button';
    edit.addEventListener('click', () => openTeamDialog(team));
    actions.append(edit);
  }

  const card = make('div', 'card');
  card.append(make('div', 'team-icon', '\u25C6'), info, actions);
  return card;
}

async function drawMembersPane() {
  const community = currentCommunity();
  if (!community) return;
  const openId = community.id;

  const count = community.members.length;
  $('memberCount').textContent = count + (count === 1 ? ' person' : ' people') + ' in ' + community.name;
  $('memberList').replaceChildren(...community.members.map(makeMemberCard));

  // Team descriptions are encrypted, so they are decrypted first
  const teams = community.channels.filter((c) => c.type === 'team');
  $('teamCount').textContent = teams.length === 0
    ? 'No teams you can see yet'
    : teams.length + (teams.length === 1 ? ' team' : ' teams');
  const cards = [];
  for (const team of teams) cards.push(makeTeamCard(team, await descriptionOf(team)));
  if (currentCommunityId !== openId) return;
  if (cards.length === 0) cards.push(make('p', 'hint', canManage() ? 'Create a team to give a group of people their own chat and files.' : 'You are not in a team yet.'));
  $('teamCards').replaceChildren(...cards);
}

/* ---------- Profile menu and settings ---------- */

$('openSettings').addEventListener('click', () => {
  drawSwatches();
  $('compactToggle').checked = settings.compact;
  $('settingsDialog').showModal();
});
$('closeSettings').addEventListener('click', () => $('settingsDialog').close());

function drawSwatches() {
  const box = $('colorChoices');
  box.replaceChildren();
  COLORS.forEach((color, index) => {
    const button = make('button', 'swatch' + (color === settings.color ? ' selected' : ''));
    button.type = 'button';
    button.style.background = color;
    button.setAttribute('aria-label', 'Profile color ' + (index + 1));
    button.addEventListener('click', () => {
      settings.color = color;
      localStorage.setItem('tv_color', color);
      drawSwatches();
      refreshAvatars();
    });
    box.append(button);
  });
}

$('compactToggle').addEventListener('change', (event) => {
  settings.compact = event.target.checked;
  localStorage.setItem('tv_compact', settings.compact ? '1' : '0');
  document.body.classList.toggle('compact', settings.compact);
});

async function signOut() {
  sessionStorage.removeItem('tv_private');
  try {
    await fetch('auth.php', { method: 'POST', body: new URLSearchParams({ action: 'logout' }) });
  } catch (error) {}
  window.location.href = 'login.html';
}
$('logoutButton').addEventListener('click', signOut);

/* ---------- Start ---------- */

async function start() {
  // 1. Only signed in users can see this page
  let who = {};
  try {
    who = await (await fetch('auth.php?action=me')).json();
  } catch (error) {}
  if (!who.username) {
    window.location.href = 'login.html';
    return;
  }
  me = who.username;

  // 2. Your private key was unlocked with your password when you signed in.
  //    If it is missing (for example a new tab), sign in again to unlock it.
  const savedKey = sessionStorage.getItem('tv_private');
  if (!savedKey || !window.crypto || !window.crypto.subtle) {
    await signOut();
    return;
  }
  privateKey = await TVCrypto.importPrivateKey(savedKey);

  // 3. Profile picture and menu
  const profile = $('profileButton');
  profile.textContent = initials(me);
  profile.dataset.name = me;
  $('menuName').textContent = me;
  document.body.classList.toggle('compact', settings.compact);
  refreshAvatars();

  // 4. Load people and communities
  renderCommunities();
  await loadPeople();
  await loadCommunities();

  // 5. Check for new people, communities, messages and files every 3 seconds
  setInterval(() => {
    loadPeople();
    loadCommunities();
    loadMessages();
    if (currentTab === 'files') loadFiles();
  }, 3000);
}

start();
