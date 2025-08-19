<?php
/*
 * ============================================
 *  KTB Manager — Perkantas (PHP + TXT/JSON)
 *  Single-file prototype by ChatGPT for Natan
 *  Requirements: PHP 7.4+
 * ============================================
 * - 2 Role: admin, user
 * - Data disimpan di folder ./data sebagai JSON array
 * - Admin: kelola kampus, user, KTB, pertemuan, absensi
 * - User: ikut KTB; jika leader KTB => kelola anggota, meeting, absensi
 *
 * Perubahan terkini:
 * - HAPUS pendaftaran umum: tidak ada menu/register page. User hanya bisa ditambahkan oleh Admin.
 * - Admin dapat menambahkan 1 user atau banyak user sekaligus (kampus sama).
 * - Data user mencakup: username, nama lengkap, telepon, kampus, angkatan, jurusan, jenis kelamin, password (hash), role.
 * - Reset PW aman (pakai formaction), tabel responsif (.table-wrap).
 * - Aksi KTB hanya di halaman "Saya"; halaman "KTB" tanpa kolom aksi.
 * - Field schedule/location untuk KTB telah dihapus dari seluruh UI & export.
 * - (BARU) Daftar pengguna: form edit disembunyikan, muncul setelah klik "Edit".
 */

date_default_timezone_set('Asia/Jakarta');

session_start();
mb_internal_encoding('UTF-8');

// -----------------------------
// Konfigurasi dasar
// -----------------------------
$APP_NAME   = 'KTB Manager';
$DATA_DIR   = __DIR__ . '/data';
$UPLOAD_DIR = $DATA_DIR . '/uploads'; // simpan foto meeting
$FILES = [
  'users'        => $DATA_DIR . '/users.txt',
  'campuses'     => $DATA_DIR . '/campuses.txt',
  'ktb_groups'   => $DATA_DIR . '/ktb_groups.txt',
  'memberships'  => $DATA_DIR . '/memberships.txt',
  'meetings'     => $DATA_DIR . '/meetings.txt',
  'attendance'   => $DATA_DIR . '/attendance.txt',
];

$ALLOWED_TYPES = ['siswa','mahasiswa','alumni'];
$ALLOWED_STATUS= ['aktif','nonaktif'];
$ATTENDANCE    = ['hadir','izin','alpha'];

// -----------------------------
// Bootstrap data folder & files
// -----------------------------
if (!file_exists($DATA_DIR)) mkdir($DATA_DIR, 0755, true);
if (!file_exists($UPLOAD_DIR)) mkdir($UPLOAD_DIR, 0755, true);
foreach ($FILES as $f) if (!file_exists($f)) file_put_contents($f, json_encode([]));

// -----------------------------
// Util JSON storage helpers
// -----------------------------
function db_read($key) {
  global $FILES;
  $path = $FILES[$key] ?? null;
  if (!$path || !file_exists($path)) return [];
  $raw = file_get_contents($path);
  $data = json_decode($raw, true);
  if (!is_array($data)) $data = [];
  return $data;
}
function db_save($key, $data) {
  global $FILES;
  $path = $FILES[$key] ?? null;
  if (!$path) return false;
  file_put_contents($path, json_encode(array_values($data), JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
  return true;
}
function gen_id() {
  return bin2hex(random_bytes(8)) . '-' . dechex(time());
}
function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function is_logged_in() { return isset($_SESSION['user']); }
function current_user() { return $_SESSION['user'] ?? null; }
function is_admin() { return is_logged_in() && ($_SESSION['user']['role'] ?? '') === 'admin'; }
function require_login() { if (!is_logged_in()) { header('Location:?action=login'); exit; } }

// CSRF
function csrf_token() {
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
  return $_SESSION['csrf'];
}
function csrf_ok($token) { return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token ?? ''); }

// -----------------------------
// Helpers domain
// -----------------------------
function get_user($username) {
  $users = db_read('users');
  foreach ($users as $u) if (strcasecmp($u['username'], $username)===0) return $u;
  return null;
}
function save_user($user) {
  $users = db_read('users');
  $found = false;
  foreach ($users as &$u) {
    if (strcasecmp($u['username'],$user['username'])===0) { $u = $user; $found=true; break; }
  }
  if (!$found) $users[] = $user;
  db_save('users',$users);
}
function delete_user($username) {
  $m = db_read('memberships');
  foreach ($m as $r) if (strcasecmp($r['username'] ?? '', $username)===0) return false;

  $att = db_read('attendance');
  foreach ($att as $a) if (strcasecmp($a['username'] ?? '', $username)===0) return false;

  $ktbs = db_read('ktb_groups');
  foreach ($ktbs as $k) {
    if (isset($k['leader']) && strcasecmp($k['leader'],$username)===0) return false;
  }

  $users = db_read('users');
  $users = array_values(array_filter($users, fn($u)=>strcasecmp($u['username'] ?? '', $username)!==0));
  db_save('users',$users);
  return true;
}
function user_exists($username) { return get_user($username) !== null; }

function get_campus($id) {
  $rows = db_read('campuses');
  foreach ($rows as $r) if ($r['id']===$id) return $r;
  return null;
}
function save_campus($row) {
  $rows = db_read('campuses');
  $found = false;
  foreach ($rows as &$r) if ($r['id']===$row['id']) { $r=$row; $found=true; break; }
  if (!$found) $rows[] = $row;
  db_save('campuses',$rows);
}
function delete_campus($id) {
  $users = db_read('users');
  foreach ($users as $u) if (($u['campus_id'] ?? '') === $id) return false;
  $ktbs = db_read('ktb_groups');
  foreach ($ktbs as $k) if (($k['campus_id'] ?? '') === $id) return false;

  $rows = db_read('campuses');
  $rows = array_values(array_filter($rows, fn($r)=>$r['id']!==$id));
  db_save('campuses',$rows);
  return true;
}

function get_ktb($id) {
  $rows = db_read('ktb_groups');
  foreach ($rows as $r) if ($r['id']===$id) return $r;
  return null;
}
function save_ktb($row) {
  $rows = db_read('ktb_groups');
  $found=false;
  foreach ($rows as &$r) if ($r['id']===$row['id']) { $r=$row; $found=true; break; }
  if (!$found) $rows[]=$row;
  db_save('ktb_groups',$rows);
}
function delete_ktb($id) {
  $m = db_read('memberships');
  foreach ($m as $r) if ($r['ktb_id'] === $id) return false;

  $meet = db_read('meetings');
  foreach ($meet as $mm) if ($mm['ktb_id'] === $id) return false;

  $rows = db_read('ktb_groups');
  $rows = array_values(array_filter($rows, fn($r)=>$r['id']!==$id));
  db_save('ktb_groups',$rows);
  return true;
}

function memberships_of_ktb($ktb_id) {
  $rows = db_read('memberships');
  return array_values(array_filter($rows, fn($r)=>$r['ktb_id']===$ktb_id));
}
function add_membership($username, $ktb_id, $role='member') {
  $rows = db_read('memberships');
  foreach ($rows as $r) {
    if ($r['ktb_id']===$ktb_id && strcasecmp($r['username'],$username)===0) return;
  }
  $rows[] = ['username'=>$username,'ktb_id'=>$ktb_id,'role'=>$role,'since'=>date('Y-m-d')];
  db_save('memberships',$rows);
}
function remove_membership($username,$ktb_id) {
  $rows = db_read('memberships');
  $rows = array_values(array_filter($rows, fn($r)=> !($r['ktb_id']===$ktb_id && strcasecmp($r['username'],$username)===0)));
  db_save('memberships',$rows);
}
function user_ktb_roles($username) {
  $rows = db_read('memberships');
  return array_values(array_filter($rows, fn($r)=>strcasecmp($r['username'],$username)===0));
}
function is_ktb_leader($username, $ktb_id) {
  $k = get_ktb($ktb_id);
  if (!$k) return false;
  if (isset($k['leader']) && strcasecmp($k['leader'],$username)===0) return true;
  $m = memberships_of_ktb($ktb_id);
  foreach ($m as $mm) if (strcasecmp($mm['username'],$username)===0 && ($mm['role']??'')==='leader') return true;
  return false;
}

function save_meeting($row) {
  $rows = db_read('meetings');
  $found=false;
  foreach ($rows as &$r) if ($r['id']===$row['id']) { $r=$row; $found=true; break; }
  if (!$found) $rows[]=$row;
  db_save('meetings',$rows);
}
function get_meeting($id) {
  $rows = db_read('meetings');
  foreach ($rows as $r) if ($r['id']===$id) return $r;
  return null;
}
function meetings_of_ktb($ktb_id) {
  $rows = db_read('meetings');
  $res = array_values(array_filter($rows, fn($r)=>$r['ktb_id']===$ktb_id));
  usort($res, fn($a,$b)=>strcmp($b['date'],$a['date']));
  return $res;
}
function delete_meeting($id) {
  $rows = db_read('meetings');
  $rows = array_values(array_filter($rows, fn($r)=>$r['id']!==$id));
  db_save('meetings',$rows);
  $att = db_read('attendance');
  $att = array_values(array_filter($att, fn($a)=>$a['meeting_id']!==$id));
  db_save('attendance',$att);
}

function set_attendance($meeting_id, $username, $status, $note='') {
  global $ATTENDANCE;
  if (!in_array($status,$ATTENDANCE,true)) $status='hadir';
  $rows = db_read('attendance');
  $found=false;
  foreach ($rows as &$r) {
    if ($r['meeting_id']===$meeting_id && strcasecmp($r['username'],$username)===0) {
      $r['status']=$status; $r['note']=$note; $found=true; break;
    }
  }
  if (!$found) $rows[] = ['meeting_id'=>$meeting_id,'username'=>$username,'status'=>$status,'note'=>$note];
  db_save('attendance',$rows);
}
function attendance_of_meeting($meeting_id) {
  $rows = db_read('attendance');
  return array_values(array_filter($rows, fn($r)=>$r['meeting_id']===$meeting_id));
}
function has_any_attendance($meeting_id) {
  $rows = db_read('attendance');
  foreach ($rows as $r) if ($r['meeting_id']===$meeting_id) return true;
  return false;
}

// -----------------------------
// Upload Foto (validasi sederhana)
// -----------------------------
function handle_photo_upload($field, $meeting_id) {
  global $UPLOAD_DIR;
  if (!isset($_FILES[$field]) || !is_uploaded_file($_FILES[$field]['tmp_name'])) return [false, null, ''];
  $file = $_FILES[$field];
  if ($file['error'] !== UPLOAD_ERR_OK) return [false, null, 'Upload gagal (error '.$file['error'].')'];

  if ($file['size'] > 6 * 1024 * 1024) return [false, null, 'Ukuran foto maksimal 6MB'];

  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime  = finfo_file($finfo, $file['tmp_name']);
  finfo_close($finfo);

  $allowed = ['image/jpeg'=>'.jpg','image/png'=>'.png','image/webp'=>'.webp'];
  if (!isset($allowed[$mime])) return [false, null, 'Format foto harus JPG/PNG/WEBP'];
  $ext = $allowed[$mime];

  $name = 'meet_'.$meeting_id.'_'.bin2hex(random_bytes(4)).$ext;
  $dest = $UPLOAD_DIR . '/'.$name;
  if (!move_uploaded_file($file['tmp_name'], $dest)) {
    return [false, null, 'Gagal menyimpan foto'];
  }
  return [true, 'data/uploads/'.$name, ''];
}

// -----------------------------
// Rekonsiliasi status pertemuan
// -----------------------------
function reconcile_meetings() {
  $meetings = db_read('meetings');
  $att = db_read('attendance');
  $attMap = [];
  foreach ($att as $a) { $attMap[$a['meeting_id']] = true; }

  $today = date('Y-m-d');
  $changed = false;

  foreach ($meetings as &$m) {
    $status = $m['status'] ?? 'scheduled';
    $hasAtt = !empty($attMap[$m['id']]);
    $hasPhoto = !empty($m['photo']);
    if ($m['date'] < $today) {
      if ($status !== 'cancelled') {
        $new = ($hasAtt && $hasPhoto) ? 'completed' : 'cancelled';
        if ($new !== $status) { $m['status'] = $new; $changed = true; }
      }
    } else {
      $new = ($hasAtt && $hasPhoto) ? 'completed' : 'scheduled';
      if ($new !== $status) { $m['status'] = $new; $changed = true; }
    }
  }
  if ($changed) db_save('meetings', $meetings);
}
reconcile_meetings();

// -----------------------------
// Auth: Login / Logout
// -----------------------------
// Action can come from query string or POST (e.g., filter forms)
$action = $_GET['action'] ?? ($_POST['action'] ?? 'dashboard');

// HAPUS pendaftaran umum: tidak ada do_register / register
if ($action==='do_login' && $_SERVER['REQUEST_METHOD']==='POST') {
  if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
  $username = trim($_POST['username'] ?? '');
  $pass     = $_POST['password'] ?? '';
  $user = get_user($username);
  if (!$user || !password_verify($pass, $user['password_hash'])) {
    $err='Login gagal.'; $action='login';
  } else {
    $_SESSION['user'] = $user;
    header('Location:?action=dashboard'); exit;
  }
}
if ($action==='logout') {
  session_destroy(); header('Location:?action=login'); exit;
}

// -----------------------------
// Admin & Leader ops (POST)
// -----------------------------

// Normalisasi gender
function normalize_gender($g){
  $g = trim(mb_strtolower((string)$g));
  if (in_array($g,['l','pria','laki','laki-laki','male','m'],true)) return 'L';
  if (in_array($g,['p','wanita','perempuan','female','f'],true)) return 'P';
  return '';
}
// Validasi angkatan (YYYY)
function normalize_angkatan($a){
  $a = trim((string)$a);
  return preg_match('/^\d{4}$/',$a) ? $a : '';
}

if (is_logged_in()) {

  // CAMPUS
  if ($action==='campus_add' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $row = [
      'id'    => gen_id(),
      'name'  => trim($_POST['name'] ?? ''),
      'city'  => trim($_POST['city'] ?? ''),
      'region'=> trim($_POST['region'] ?? ''),
      'contact_name' => trim($_POST['contact_name'] ?? ''),
      'contact_phone'=> trim($_POST['contact_phone'] ?? ''),
      'created_at' => date('c')
    ];
    if ($row['name']==='') $msg='Nama kampus/unit wajib.';
    else { save_campus($row); $msg='Kampus ditambahkan.'; }
    header('Location:?action=campuses'); exit;
  }
  if ($action==='campus_update' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $id = $_POST['id'] ?? '';
    $row = get_campus($id); if ($row) {
      foreach (['name','city','region','contact_name','contact_phone'] as $k) $row[$k] = trim($_POST[$k] ?? '');
      save_campus($row); $msg='Kampus diperbarui.';
    }
    header('Location:?action=campuses'); exit;
  }
  if ($action==='campus_delete' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    if (delete_campus($_POST['id'] ?? '')) $msg='Kampus dihapus.';
    else $msg='Kampus masih dipakai, tidak dapat dihapus.';
    header('Location:?action=campuses'); exit;
  }

  // USERS (admin) — tambah, edit, reset, bulk
  if ($action==='user_add' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');

    $username = trim($_POST['username'] ?? '');
    $name     = trim($_POST['name'] ?? '');
    $phone    = trim($_POST['phone'] ?? '');
    $campus_id= trim($_POST['campus_id'] ?? '');
    $angkatan = normalize_angkatan($_POST['angkatan'] ?? '');
    $jurusan  = trim($_POST['jurusan'] ?? '');
    $gender   = normalize_gender($_POST['gender'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $role     = in_array($_POST['role'] ?? '', ['user','admin'], true) ? $_POST['role'] : 'user';

    if ($username==='' || $password==='') {
      $msg='Username dan password wajib.';
    } elseif (user_exists($username)) {
      $msg='Username sudah dipakai.';
    } else {
      if ($campus_id !== '' && !get_campus($campus_id)) $campus_id = '';
      $user = [
        'username'      => $username,
        'name'          => $name ?: $username,
        'phone'         => $phone,
        'campus_id'     => $campus_id,
        'angkatan'      => $angkatan,
        'jurusan'       => $jurusan,
        'gender'        => $gender,
        'role'          => $role,
        'password_hash' => password_hash($password, PASSWORD_BCRYPT),
        'created_at'    => date('c')
      ];
      save_user($user);
      $msg='Pengguna ditambahkan.';
    }
    header('Location:?action=users'); exit;
  }

  if ($action==='user_bulk_add' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');

    $campus_id = trim($_POST['campus_id'] ?? '');
    if ($campus_id !== '' && !get_campus($campus_id)) $campus_id = '';

    $lines_raw = (string)($_POST['bulk_lines'] ?? '');
    $lines = preg_split("/\r\n|\n|\r/", $lines_raw);
    $ok = 0; $skip = 0; $errCount = 0;

    foreach ($lines as $line) {
      if (trim($line)==='') continue;
      $parts = preg_split('/[|,;]+/', $line);
      $parts = array_map('trim', $parts);
      $parts = array_pad($parts, 7, '');
      list($username,$name,$phone,$angkatan,$jurusan,$gender,$password) = $parts;

      if ($username==='' || $password==='') { $errCount++; continue; }
      if (user_exists($username)) { $skip++; continue; }

      $user = [
        'username'      => $username,
        'name'          => $name ?: $username,
        'phone'         => $phone,
        'campus_id'     => $campus_id,
        'angkatan'      => normalize_angkatan($angkatan),
        'jurusan'       => $jurusan,
        'gender'        => normalize_gender($gender),
        'role'          => 'user',
        'password_hash' => password_hash($password, PASSWORD_BCRYPT),
        'created_at'    => date('c')
      ];
      save_user($user);
      $ok++;
    }

    $msg = "Bulk add selesai: berhasil $ok, duplikat $skip, gagal $errCount.";
    header('Location:?action=users'); exit;
  }

  if ($action==='user_update' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $u = get_user($_POST['username'] ?? '');
    if ($u) {
      $role = in_array($_POST['role'] ?? '', ['admin','user'], true) ? $_POST['role'] : ($u['role'] ?? 'user');
      $campus_id = trim($_POST['campus_id'] ?? ($u['campus_id'] ?? ''));
      if ($campus_id !== '' && !get_campus($campus_id)) $campus_id = '';

      $u['role']      = $role;
      $u['name']      = trim($_POST['name'] ?? ($u['name'] ?? ''));
      $u['phone']     = trim($_POST['phone'] ?? ($u['phone'] ?? ''));
      $u['campus_id'] = $campus_id;
      $u['angkatan']  = normalize_angkatan($_POST['angkatan'] ?? ($u['angkatan'] ?? ''));
      $u['jurusan']   = trim($_POST['jurusan'] ?? ($u['jurusan'] ?? ''));
      $u['gender']    = normalize_gender($_POST['gender'] ?? ($u['gender'] ?? ''));

      save_user($u);
      if (isset($_SESSION['user']) && strcasecmp($_SESSION['user']['username'],$u['username'])===0) $_SESSION['user']=$u;
      $msg='Data pengguna diperbarui.';
    }
    header('Location:?action=users'); exit;
  }

  if ($action==='user_resetpw' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $u = get_user($_POST['username'] ?? '');
    if ($u) {
      $new = $_POST['newpw'] ?? '12345678';
      $u['password_hash'] = password_hash($new, PASSWORD_BCRYPT);
      save_user($u);
      $msg='Password direset.';
    }
    header('Location:?action=users'); exit;
  }

  if ($action==='user_delete' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $uname = $_POST['username'] ?? '';
    if ($uname !== '') {
      if (delete_user($uname)) {
        if (isset($_SESSION['user']) && strcasecmp($_SESSION['user']['username'],$uname)===0) unset($_SESSION['user']);
        $msg='Pengguna dihapus.';
      } else {
        $msg='Pengguna masih memiliki relasi, tidak dapat dihapus.';
      }
    }
    header('Location:?action=users'); exit;
  }

  // KTB ADD (ADMIN ATAU USER BIASA -> otomatis leader)
  if ($action==='ktb_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    global $ALLOWED_STATUS,$ALLOWED_TYPES;

    $isAdmin = is_admin();
    $leader  = $isAdmin ? trim($_POST['leader'] ?? '') : (current_user()['username'] ?? '');
    $statusKtb = $isAdmin
      ? (in_array($_POST['status'] ?? '', $ALLOWED_STATUS,true) ? $_POST['status'] : 'aktif')
      : 'aktif';

    if ($leader==='' || !user_exists($leader)) {
      $msg = 'Pemimpin wajib dan harus username yang sudah terdaftar.';
      header('Location:?action=ktb'); exit;
    }

    $row = [
      'id' => gen_id(),
      'campus_id' => $_POST['campus_id'] ?? '',
      'name' => trim($_POST['name'] ?? ''),
      'type' => in_array($_POST['type'] ?? '', $ALLOWED_TYPES,true) ? $_POST['type'] : 'mahasiswa',
      'status'=> $statusKtb,
      'leader'=> $leader,
      'created_at' => date('c')
    ];

    if ($row['name']==='' || $row['campus_id']==='') {
      $msg='Nama & kampus wajib.'; header('Location:?action=ktb'); exit;
    }

    save_ktb($row);
    add_membership($row['leader'],$row['id'],'leader');
    $msg='KTB dibuat.';
    header('Location:?action=ktb'); exit;
  }

  // KTB UPDATE — hanya admin/leader
  if ($action==='ktb_update' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $id = $_POST['id'] ?? '';
    $ktb = get_ktb($id);
    if ($ktb && (is_admin() || is_ktb_leader(current_user()['username'],$id))) {
      global $ALLOWED_STATUS,$ALLOWED_TYPES;
      $oldLeader = $ktb['leader'] ?? '';
      $newLeader = trim($_POST['leader'] ?? $oldLeader);

      $ktb['name'] = trim($_POST['name'] ?? $ktb['name']);
      $ktb['campus_id'] = $_POST['campus_id'] ?? $ktb['campus_id'];
      $ktb['type'] = in_array($_POST['type'] ?? '',$ALLOWED_TYPES,true) ? $_POST['type'] : $ktb['type'];
      $ktb['status'] = in_array($_POST['status'] ?? '',$ALLOWED_STATUS,true) ? $_POST['status'] : $ktb['status'];

      if ($newLeader === '' || !user_exists($newLeader)) {
        save_ktb($ktb);
        $msg='Perubahan disimpan kecuali Pemimpin: leader wajib & harus username terdaftar.';
      } else {
        $ktb['leader'] = $newLeader;
        save_ktb($ktb);
        if ($oldLeader !== $newLeader) {
          if ($oldLeader!=='') remove_membership($oldLeader,$ktb['id']);
          add_membership($newLeader,$ktb['id'],'leader');
        }
        $msg='KTB diperbarui.';
      }
    }
    header('Location:?action=my'); exit;
  }

  if ($action==='ktb_delete' && $_SERVER['REQUEST_METHOD']==='POST' && is_admin()) {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    if (delete_ktb($_POST['id'] ?? '')) $msg='KTB dihapus.';
    else $msg='KTB masih memiliki relasi, tidak dapat dihapus.';
    header('Location:?action=my'); exit;
  }

  // MEMBERSHIP (hanya leader/admin)
  if ($action==='member_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $ktb_id = $_POST['ktb_id'] ?? '';
    if (is_admin() || is_ktb_leader(current_user()['username'],$ktb_id)) {
      $uname = trim($_POST['username'] ?? '');
      if ($uname==='' || !user_exists($uname)) { $msg='User tidak ditemukan.'; }
      else { add_membership($uname,$ktb_id,'member'); $msg='Anggota ditambahkan.'; }
      header('Location:?action=ktb_members&ktb_id='.urlencode($ktb_id)); exit;
    } else { header('Location:?action=dashboard'); exit; }
  }
  if ($action==='member_remove' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $ktb_id = $_POST['ktb_id'] ?? '';
    if (is_admin() || is_ktb_leader(current_user()['username'],$ktb_id)) {
      $uname = $_POST['username'] ?? '';
      remove_membership($uname,$ktb_id); $msg='Anggota dihapus.';
      header('Location:?action=ktb_members&ktb_id='.urlencode($ktb_id)); exit;
    } else { header('Location:?action=dashboard'); exit; }
  }

  // MEETING (hanya leader/admin)
  if ($action==='meeting_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $ktb_id = $_POST['ktb_id'] ?? '';
    if (is_admin() || is_ktb_leader(current_user()['username'],$ktb_id)) {
      $row = [
        'id' => gen_id(),
        'ktb_id' => $ktb_id,
        'date' => $_POST['date'] ?: date('Y-m-d'),
        'topic'=> trim($_POST['topic'] ?? ''),
        'notes'=> trim($_POST['notes'] ?? ''),
        'created_at'=> date('c'),
        'status' => 'scheduled',
        'photo'  => ''
      ];
      save_meeting($row); $msg='Pertemuan dibuat. Setelah selesai, serahkan absensi & upload foto.';
      header('Location:?action=meetings&ktb_id='.urlencode($ktb_id)); exit;
    } else { header('Location:?action=dashboard'); exit; }
  }
  if ($action==='meeting_delete' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $meeting_id = $_POST['meeting_id'] ?? '';
    $m = get_meeting($meeting_id);
    if ($m && (is_admin() || is_ktb_leader(current_user()['username'],$m['ktb_id']))) {
      delete_meeting($meeting_id); $msg='Pertemuan dihapus.';
      header('Location:?action=meetings&ktb_id='.urlencode($m['ktb_id'])); exit;
    } else { header('Location:?action=dashboard'); exit; }
  }

  // ATTENDANCE + FOTO (hanya leader/admin)
  if ($action==='attendance_set' && $_SERVER['REQUEST_METHOD']==='POST') {
    if (!csrf_ok($_POST['csrf'] ?? '')) die('CSRF invalid');
    $meeting_id = $_POST['meeting_id'] ?? '';
    $m = get_meeting($meeting_id);
    if ($m && (is_admin() || is_ktb_leader(current_user()['username'],$m['ktb_id']))) {
      $today = date('Y-m-d');
      if ($m['date'] > $today) {
        $msg='Absensi & foto hanya bisa diserahkan pada tanggal pertemuan atau setelahnya.';
        header('Location:?action=attendance&meeting_id='.urlencode($meeting_id)); exit;
      }
      foreach (($_POST['status'] ?? []) as $username=>$status) {
        $note = $_POST['note'][$username] ?? '';
        set_attendance($meeting_id, $username, $status, $note);
      }
      $meet = get_meeting($meeting_id);
      if (empty($meet['photo'])) {
        [$ok, $path, $errUp] = handle_photo_upload('report_photo', $meeting_id);
        if ($ok && $path) { $meet['photo'] = $path; save_meeting($meet); }
        elseif ($errUp) { $msg = 'Absensi disimpan, unggah foto gagal: '.$errUp; header('Location:?action=attendance&meeting_id='.urlencode($meeting_id)); exit; }
      }
      $meet = get_meeting($meeting_id);
      if (($meet['photo'] ?? '') !== '' && has_any_attendance($meeting_id)) {
        $meet['status'] = 'completed'; save_meeting($meet);
        $msg='Laporan pertemuan lengkap (absensi + foto) tersimpan.';
      } else {
        $msg='Absensi disimpan. Lengkapi dengan foto agar tidak dibatalkan.';
      }
      header('Location:?action=attendance&meeting_id='.urlencode($meeting_id)); exit;
    } else { header('Location:?action=dashboard'); exit; }
  }

  // EXPORT
  if ($action==='export_ktb_csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="ktb_export.csv"');
    $out = fopen('php://output','w');
    fputcsv($out, ['id','name','type','status','campus','leader']);
    $campuses = db_read('campuses'); $campMap=[];
    foreach ($campuses as $c) $campMap[$c['id']] = $c['name'];
    foreach (db_read('ktb_groups') as $k) {
      fputcsv($out, [
        $k['id'],$k['name'],$k['type'],$k['status'],
        $campMap[$k['campus_id']] ?? $k['campus_id'],
        $k['leader'] ?? ''
      ]);
    }
    exit;
  }
  if ($action==='export_attendance_csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="attendance_export.csv"');
    $out = fopen('php://output','w');
    fputcsv($out, ['meeting_id','ktb_name','date','username','status','note']);
    $ktbMap=[]; foreach (db_read('ktb_groups') as $k) $ktbMap[$k['id']]=$k['name'];
    $meetMap=[]; foreach (db_read('meetings') as $m) $meetMap[$m['id']]=$m;
    foreach (db_read('attendance') as $a) {
      $m = $meetMap[$a['meeting_id']] ?? null;
      fputcsv($out, [
        $a['meeting_id'],
        $m ? ($ktbMap[$m['ktb_id']] ?? $m['ktb_id']) : '',
        $m['date'] ?? '',
        $a['username'],
        $a['status'],
        $a['note']
      ]);
    }
    exit;
  }
}

// -----------------------------
// HTML Helpers (UI formal + responsif)
// -----------------------------
function layout_header($title) {
  global $APP_NAME;
  $u = current_user();
  echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
  echo '<title>'.e($APP_NAME).' — '.e($title).'</title>';
  echo '<style>
  :root{
    --bg:#0b1020;--card:#121a33;--muted:#8aa0c6;--text:#eef3ff;--accent:#4f7cff;--danger:#ff5d6c;--ok:#3ccf91;--warn:#ffb020
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;color:var(--text);background:linear-gradient(180deg,#0b1020,#121a33)}
  a{color:#aecdff;text-decoration:none}
  a:hover{text-decoration:underline}
  header{
    display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:#0e1530;
    position:sticky;top:0;z-index:5;border-bottom:1px solid #1f2b55;gap:10px
  }
  .brand{font-weight:700;letter-spacing:.3px;font-size:1rem;white-space:nowrap}
  .menu{display:flex;gap:8px;overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}
  .menu a{
    display:inline-flex;align-items:center;justify-content:center;padding:8px 10px;
    background:#0f1731;border:1px solid #2a3b76;border-radius:10px;font-size:13px;flex:0 0 auto;color:#e9f0ff
  }
  .menu a.right{margin-left:auto}
  .container{max-width:1100px;margin:20px auto;padding:0 12px}
  .card{background:var(--card);border:1px solid #23305f;border-radius:14px;padding:14px;margin-bottom:14px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .col{flex:1 1 280px}
  input,select,textarea{width:100%;padding:9px;border-radius:10px;border:1px solid #2a3b76;background:#0f1731;color:#e9f0ff;font-size:14px}
  label{font-size:.9rem;color:#c8d7ff;margin-bottom:6px;display:block}
  button{background:var(--accent);border:0;border-radius:12px;padding:9px 12px;color:#fff;cursor:pointer;font-weight:600;font-size:14px}
  .btn-danger{background:var(--danger)}
  .btn-ghost{background:transparent;border:1px solid #2a3b76;color:#e9f0ff}
  .btn-icon{display:inline-flex;align-items:center;gap:6px}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem;border:1px solid #2a3b76}
  .muted{color:var(--muted)} .ok{color:var(--ok)} .danger{color:var(--danger)} .warn{color:var(--warn)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
  .right{float:right}
  .mt4{margin-top:4px} .mt8{margin-top:8px} .mb8{margin-bottom:8px} .mt16{margin-top:16px} .mb16{margin-bottom:16px}
  .nowrap{white-space:nowrap}
  .status{font-weight:700}
  .status-scheduled{color:#aecdff}
  .status-completed{color:#3ccf91}
  .status-cancelled{color:#ff5d6c}
  img.thumb{max-width:120px;border-radius:8px;border:1px solid #2a3b76}

  .filter-inline{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end}
  .filter-inline div{flex:0 0 auto}
  .filter-inline input,.filter-inline select{width:auto}
  @media(max-width:600px){
    .filter-inline{flex-direction:column}
    .filter-inline div{width:100%}
    .filter-inline input,.filter-inline select{width:100%}
  }

  .chart-row{display:flex;flex-wrap:wrap;gap:16px}
  .chart-row .card{flex:1 1 260px}
  .chart-row canvas{max-width:100%;height:auto}
  @media(max-width:600px){.chart-row{flex-direction:column}}

  /* Tabel responsive via wrapper */
  .table-wrap{width:100%;overflow-x:auto}
  table{width:100%;border-collapse:collapse;min-width:720px}
  th,td{padding:8px 10px;border-bottom:1px solid #2a3b76;vertical-align:top}
  th{text-align:left;color:#cfe2ff;font-weight:600}

  @media (max-width: 600px){
    .brand{font-size:.9rem}
    header{padding:8px 10px}
    .menu a{padding:7px 9px;font-size:12px}
    .container{padding:0 10px}
    .card{padding:12px}
    th,td{padding:6px 8px;font-size:13px}
    input,select,textarea{font-size:13px}
    button{padding:8px 10px;font-size:13px;border-radius:10px}
    table{min-width:640px}
  }
  details > summary{cursor:pointer;color:#aecdff}
  details{display:inline-block}
  </style></head><body>';
  echo '<header><div class="brand">'.e($APP_NAME).'</div><nav class="menu">';
  $u = current_user();
  if ($u) {
    echo '<a href="?action=dashboard" title="Dashboard">Dashboard</a>';
    if (is_admin()) {
      echo '<a href="?action=campuses" title="Kampus/Unit">Kampus</a>';
      echo '<a href="?action=users" title="Pengguna">Users</a>';
      echo '<a href="?action=analysis" title="Analisis Data">Analisis</a>';
    }
    echo '<a href="?action=ktb" title="Kelola KTB">KTB</a>';
    echo '<a href="?action=my" title="Profil Saya">Saya</a>';
    echo '<a class="right" href="?action=logout" title="Logout">Logout ('.e($u['username']).')</a>';
  } else {
    echo '<a href="?action=login" title="Login">Login</a>';
  }
  echo '</nav></header><div class="container">';
}
function layout_footer(){
  echo <<<'HTML'
<script>
document.addEventListener("submit", function(e){
  var form = e.target;
  if(form.tagName === "FORM"){
    e.preventDefault();
    var method = (form.method || "GET").toUpperCase();
    var url = form.action || window.location.href;
    var options = { method: method };
    if(method === "GET"){
      var params = new URLSearchParams(new FormData(form)).toString();
      if(params){
        url += (url.indexOf("?") === -1 ? "?" : "&") + params;
      }
    } else {
      options.body = new FormData(form);
    }
    fetch(url, options).then(function(res){ return res.text(); }).then(function(html){
      document.open(); document.write(html); document.close();
    });
  }
});
document.addEventListener("click", function(e){
  var a = e.target.closest("a");
  if(a && a.getAttribute("href") && !a.getAttribute("target") && !a.getAttribute("href").startsWith("#")){
    e.preventDefault();
    fetch(a.getAttribute("href")).then(function(res){ return res.text(); }).then(function(html){
      document.open(); document.write(html); document.close();
    });
  }
});
</script></div></body></html>
HTML;
}
function flash_msg($msg) { if (!$msg) return; echo '<div class="card">'.e($msg).'</div>'; }

// -----------------------------
// VIEWS
// -----------------------------
$err = $err ?? ''; $msg = $msg ?? '';

if ($action==='login') {
  layout_header('Login');
  flash_msg($err);
  $csrf = csrf_token();
  echo '<div class="card" style="max-width:460px;margin:40px auto">
    <h2>Masuk</h2>
    <form method="post" action="?action=do_login">
      <input type="hidden" name="csrf" value="'.e($csrf).'">
      <label>Username</label><input name="username" autocomplete="username" required>
      <label class="mt8">Password</label><input type="password" name="password" autocomplete="current-password" required>
      <div class="mt16"><button class="btn-icon" title="Login">Login</button></div>
    </form></div>';
  layout_footer(); exit;
}

require_login();

// DASHBOARD
if ($action==='dashboard') {
  layout_header('Dashboard');
  flash_msg($msg);
  $campuses = db_read('campuses');
  $ktbs     = db_read('ktb_groups');
  $users    = db_read('users');
  $meetings = db_read('meetings');
  echo '<div class="grid">';
  echo card_stat('Kampus', count($campuses));
  echo card_stat('KTB', count($ktbs));
  echo card_stat('Pengguna', count($users));
  echo card_stat('Pertemuan', count($meetings));
  echo '</div>';

  // Pertemuan terbaru
  $ktbMap=[]; foreach ($ktbs as $k) $ktbMap[$k['id']]=$k['name'];
  usort($meetings, fn($a,$b)=>strcmp($b['date'],$a['date']));
  echo '<div class="card"><h3>Pertemuan Terbaru</h3><div class="table-wrap"><table><tr><th>Tanggal</th><th>KTB</th><th>Topik</th><th>Status</th><th class="nowrap">Aksi</th></tr>';
  foreach (array_slice($meetings,0,8) as $m) {
    $st = e($m['status'] ?? 'scheduled');
    $canReport = is_admin() || is_ktb_leader(current_user()['username'],$m['ktb_id']);
    echo '<tr><td>'.e($m['date']).'</td><td>'.e($ktbMap[$m['ktb_id']] ?? $m['ktb_id']).'</td><td>'.e($m['topic']).'</td>';
    echo '<td class="status status-'.e($st).'">'.e($st).'</td>';
    echo '<td class="nowrap">'.($canReport ? '<a href="?action=attendance&meeting_id='.e($m['id']).'" title="Laporan">Laporan</a>' : '<span class="muted">-</span>').'</td></tr>';
  }
  echo '</table></div></div>';
  layout_footer(); exit;
}
function card_stat($label,$value){
  return '<div class="card"><div class="muted">'.$label.'</div><div style="font-size:2rem;font-weight:800">'.e($value).'</div></div>';
}

// ANALYSIS (admin)
if ($action==='analysis') {
  if (!is_admin()) { header('Location:?action=dashboard'); exit; }

  layout_header('Analisis Data');

  // filters
  $campus_id = $_POST['campus_id'] ?? '';
  $angkatan  = $_POST['angkatan'] ?? '';
  $start     = $_POST['start'] ?? '';
  $end       = $_POST['end'] ?? '';

  $campuses = db_read('campuses');
  $users    = db_read('users');
  $meetings     = db_read('meetings');
  $ktb          = db_read('ktb_groups');
  $memberships  = db_read('memberships');

  // maps for quick lookup
  $ktbMap  = []; foreach ($ktb as $k) $ktbMap[$k['id']] = $k;
  $userMap = []; foreach ($users as $u) $userMap[strtolower($u['username'])] = $u;

  // map each KTB to its leader's angkatan
  $ktbLeaderAng = [];
  foreach ($memberships as $m) {
    if (($m['role'] ?? '') !== 'leader') continue;
    $u = $userMap[strtolower($m['username'])] ?? null;
    if ($u) $ktbLeaderAng[$m['ktb_id']] = $u['angkatan'] ?? '';
  }
  $angkatanOpts = array_unique(array_filter(array_values($ktbLeaderAng)));
  sort($angkatanOpts);

  // summary counts for KTB, unique leaders, and members
  $ktbCount = 0;
  foreach ($ktb as $k) {
    if ($campus_id && (($k['campus_id'] ?? '') !== $campus_id)) continue;
    if ($angkatan && (($ktbLeaderAng[$k['id']] ?? '') !== $angkatan)) continue;
    $ktbCount++;
  }
  $uniqueUsers = [];
  $uniqueLeaders = [];
  foreach ($memberships as $m) {
    $kt = $ktbMap[$m['ktb_id']] ?? null;
    if (!$kt) continue;
    if ($campus_id && (($kt['campus_id'] ?? '') !== $campus_id)) continue;
    if ($angkatan && (($ktbLeaderAng[$m['ktb_id']] ?? '') !== $angkatan)) continue;
    $u = $userMap[strtolower($m['username'])] ?? null;
    if (!$u) continue;
    $un = strtolower($m['username']);
    $uniqueUsers[$un] = true;
    if (($m['role'] ?? '') === 'leader') $uniqueLeaders[$un] = true;
  }
  $leaderCount = count($uniqueLeaders);
  $memberCount = max(0, count($uniqueUsers) - $leaderCount);

  // meeting counts per KTB for pie chart
  $meetingCounts = [];
  foreach ($meetings as $m) {
    if ($start && ($m['date'] ?? '') < $start) continue;
    if ($end && ($m['date'] ?? '') > $end) continue;
    $kt = $ktbMap[$m['ktb_id']] ?? null;
    if (!$kt) continue;
    if ($campus_id && (($kt['campus_id'] ?? '') !== $campus_id)) continue;
    if ($angkatan && (($ktbLeaderAng[$m['ktb_id']] ?? '') !== $angkatan)) continue;
    $name = $kt['name'] ?? ('KTB '.$m['ktb_id']);
    if (!isset($meetingCounts[$name])) $meetingCounts[$name] = 0;
    $meetingCounts[$name]++;
  }
  $meetingTotal = array_sum($meetingCounts);

  // Filter form
  echo '<div class="card"><h3>Filter</h3><form method="post" action="?action=analysis" class="filter-inline">';
  echo '<div><label>Kampus</label><select name="campus_id"><option value="">-- Semua --</option>';
  foreach ($campuses as $c) {
    $sel = $campus_id === ($c['id'] ?? '') ? 'selected' : '';
    echo '<option value="'.e($c['id']).'" '.$sel.'>'.e($c['name']).'</option>';
  }
  echo '</select></div>';
  echo '<div><label>Angkatan</label><select name="angkatan"><option value="">-- Semua --</option>';
  foreach ($angkatanOpts as $ang) {
    $sel = $angkatan === $ang ? 'selected' : '';
    echo '<option value="'.e($ang).'" '.$sel.'>'.e($ang).'</option>';
  }
  echo '</select></div>';
  echo '<div><label>Dari Tanggal</label><input type="date" name="start" value="'.e($start).'"></div>';
  echo '<div><label>Sampai Tanggal</label><input type="date" name="end" value="'.e($end).'"></div>';
  echo '</form></div>';
  echo '<script>document.querySelectorAll(".filter-inline input,.filter-inline select").forEach(el=>el.addEventListener("change",()=>el.form.submit()));</script>';

  echo '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>';

  echo '<div class="chart-row">';

  echo '<div class="card"><h3>Statistik KTB</h3>';
  $sumAll = $ktbCount + $leaderCount + $memberCount + $meetingTotal;
  if ($sumAll === 0) {
    echo '<div class="muted">Belum ada data untuk filter ini.</div>';
  } else {
    echo '<canvas id="chartKTB" width="300" height="220"></canvas>';
    echo '<ul>';
    echo '<li>Jumlah KTB: '.e($ktbCount).'</li>';
    echo '<li>Jumlah Pemimpin: '.e($leaderCount).'</li>';
    echo '<li>Jumlah Adek: '.e($memberCount).'</li>';
    echo '<li>Jumlah Pertemuan: '.e($meetingTotal).'</li>';
    echo '</ul>';
    echo '<script>new Chart(document.getElementById("chartKTB").getContext("2d"),{type:"bar",data:{labels:["KTB","Pemimpin","Adek","Pertemuan"],datasets:[{data:['.$ktbCount.','.$leaderCount.','.$memberCount.','.$meetingTotal.'],backgroundColor:["#2196f3","#9c27b0","#ffc107","#4caf50"]}]},options:{plugins:{legend:{display:false}}}});</script>';
  }
  echo '</div>';

  echo '<div class="card"><h3>Ringkasan Pertemuan</h3>';
  if (!$meetingCounts) {
    echo '<div class="muted">Belum ada data untuk filter ini.</div>';
  } else {
    $labels = array_map('e', array_keys($meetingCounts));
    $dataVals = array_values($meetingCounts);
    $colors = [];
    $countLabels = count($labels);
    for ($i=0;$i<$countLabels;$i++) $colors[] = 'hsl('.(360*$i/$countLabels).',70%,60%)';
    echo '<canvas id="chartMeeting" width="300" height="220"></canvas>';
    echo '<ul>';
    foreach ($meetingCounts as $k=>$v) echo '<li>'.e($k).': '.e($v).'</li>';
    echo '</ul>';
    echo '<script>new Chart(document.getElementById("chartMeeting").getContext("2d"),{type:"pie",data:{labels:["'.implode('","',$labels).'"],datasets:[{data:['.implode(',', $dataVals).'],backgroundColor:["'.implode('","',$colors).'"]}]}});</script>';
  }
  echo '</div>';

  echo '</div>';

  layout_footer(); exit;
}

// CAMPUSES (admin)
if ($action==='campuses') {
  if (!is_admin()) { header('Location:?action=dashboard'); exit; }
  layout_header('Kampus');
  flash_msg($msg);
  $csrf = csrf_token();
  echo '<div class="row"><div class="col"><div class="card"><h3>Tambah Kampus</h3>
  <form method="post" action="?action=campus_add">
    <input type="hidden" name="csrf" value="'.e($csrf).'">
    <label>Nama Kampus/Unit</label><input name="name" required>
    <label class="mt8">Kota</label><input name="city">
    <label class="mt8">Wilayah</label><input name="region" placeholder="mis. Jatim">
    <label class="mt8">Kontak (Nama)</label><input name="contact_name">
    <label class="mt8">Kontak (Telepon)</label><input name="contact_phone">
    <div class="mt16"><button class="btn-icon" title="Tambah kampus">Tambah</button></div>
  </form></div></div>';

  echo '<div class="col"><div class="card"><h3>Daftar Kampus</h3>';
  $rows = db_read('campuses');
  if (!$rows) echo '<div class="muted">Belum ada data.</div>';
  else {
    echo '<div class="table-wrap"><table><tr><th>Nama</th><th>Wilayah</th><th>Kota</th><th>Kontak</th><th></th></tr>';
    foreach ($rows as $r) {
      echo '<tr><td>'.e($r['name']).'</td><td>'.e($r['region']).'</td><td>'.e($r['city']).'</td>';
      echo '<td>'.e(($r['contact_name']??'').($r['contact_phone']? ' ('.$r['contact_phone'].')':'' )).'</td><td class="nowrap">';
      echo '<details><summary title="Edit">Edit</summary><form method="post" action="?action=campus_update" class="mt8">
      <input type="hidden" name="csrf" value="'.e($csrf).'">
      <input type="hidden" name="id" value="'.e($r['id']).'">
      <label>Nama</label><input name="name" value="'.e($r['name']).'">
      <label>Wilayah</label><input name="region" value="'.e($r['region']).'">
      <label>Kota</label><input name="city" value="'.e($r['city']).'">
      <label>Kontak (Nama)</label><input name="contact_name" value="'.e($r['contact_name']).'">
      <label>Kontak (Telp)</label><input name="contact_phone" value="'.e($r['contact_phone']).'">
      <div class="mt8"><button class="btn-icon" title="Simpan">Simpan</button></div></form></details> ';
      echo '<form method="post" action="?action=campus_delete" onsubmit="return confirm(\'Hapus?\')" style="display:inline">
        <input type="hidden" name="csrf" value="'.e($csrf).'">
        <input type="hidden" name="id" value="'.e($r['id']).'">
        <button class="btn-danger" title="Hapus">Hapus</button></form></td></tr>';
    }
    echo '</table></div>';
  }
  echo '</div></div></div>';
  layout_footer(); exit;
}

// USERS (admin) — Tambah 1, Tambah Massal, Daftar (Edit tersembunyi)
if ($action==='users') {
  if (!is_admin()) { header('Location:?action=dashboard'); exit; }
  layout_header('Pengguna');
  flash_msg($msg);
  $csrf = csrf_token();
  $users = db_read('users');
  $campuses = db_read('campuses'); $campMap=[]; foreach($campuses as $c) $campMap[$c['id']]=$c['name'];

  // Tambah 1 pengguna
  echo '<div class="card"><h3>Tambah Pengguna Baru</h3>
  <form method="post" action="?action=user_add">
    <input type="hidden" name="csrf" value="'.e($csrf).'">
    <div class="row">
      <div class="col"><label>Username</label><input name="username" required></div>
      <div class="col"><label>Nama Lengkap</label><input name="name" required></div>
      <div class="col"><label>No. Telepon</label><input name="phone"></div>
    </div>
    <div class="row">
      <div class="col"><label>Kampus</label><select name="campus_id">
        <option value="">- pilih kampus -</option>';
        foreach ($campuses as $c) echo '<option value="'.e($c['id']).'">'.e($c['name']).'</option>';
  echo '</select></div>
      <div class="col"><label>Angkatan (YYYY)</label><input name="angkatan" placeholder="2022"></div>
      <div class="col"><label>Jurusan</label><input name="jurusan"></div>
    </div>
    <div class="row">
      <div class="col"><label>Jenis Kelamin</label>
        <select name="gender"><option value="">-</option><option value="L">L</option><option value="P">P</option></select>
      </div>
      <div class="col"><label>Password</label><input type="password" name="password" required></div>
      <div class="col"><label>Peran</label>
        <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      </div>
    </div>
    <div class="mt8"><button class="btn-icon" title="Tambah Pengguna">Tambah</button></div>
  </form></div>';

  // Tambah massal
  echo '<div class="card"><h3>Tambah Banyak Pengguna (Massal)</h3>
  <form method="post" action="?action=user_bulk_add">
    <input type="hidden" name="csrf" value="'.e($csrf).'">
    <div class="row">
      <div class="col"><label>Kampus (untuk semua baris)</label><select name="campus_id">
        <option value="">- pilih kampus -</option>';
        foreach ($campuses as $c) echo '<option value="'.e($c['id']).'">'.e($c['name']).'</option>';
  echo '</select></div>
    </div>
    <label class="mt8">Daftar (satu baris per pengguna)</label>
    <textarea name="bulk_lines" rows="6" placeholder="username | nama lengkap | telepon | angkatan | jurusan | jenis kelamin | password"></textarea>
    <div class="muted mt4">Pisahkan dengan <b>|</b>, boleh juga koma/semicolon. Contoh:<br>
    <code>andi01 | Andi Saputra | 08123456789 | 2023 | Informatika | L | rahasia123</code></div>
    <div class="mt8"><button class="btn-icon" title="Proses Tambah Massal">Proses</button></div>
  </form></div>';

  // Daftar pengguna — form edit disembunyikan di <details>
  echo '<div class="card"><h3>Daftar Pengguna</h3>';
  if (!$users) {
    echo '<div class="muted">Belum ada pengguna. Tambahkan melalui formulir di atas.</div>';
  } else {
    echo '<div class="table-wrap"><table><tr>
      <th>Username</th><th>Nama</th><th>Telepon</th><th>Kampus</th><th>Angkatan</th><th>Jurusan</th><th>JK</th><th>Peran</th><th>Aksi</th></tr>';
    foreach ($users as $u) {
      $unameSafe = e($u['username']);
      echo '<tr>
        <td>'.$unameSafe.'</td>
        <td>'.e($u['name'] ?? '').'</td>
        <td>'.e($u['phone'] ?? '').'</td>
        <td>'.e($campMap[$u['campus_id'] ?? ''] ?? '').'</td>
        <td>'.e($u['angkatan'] ?? '').'</td>
        <td>'.e($u['jurusan'] ?? '').'</td>
        <td>'.e($u['gender'] ?? '').'</td>
        <td>'.e($u['role'] ?? 'user').'</td>
        <td class="nowrap">
          <details>
            <summary>Edit</summary>
            <form method="post" action="?action=user_update" class="mt8" style="min-width:280px">
              <input type="hidden" name="csrf" value="'.e($csrf).'">
              <input type="hidden" name="username" value="'.$unameSafe.'">

              <div class="row">
                <div class="col" style="flex:1 1 180px">
                  <label>Nama</label>
                  <input name="name" value="'.e($u['name'] ?? '').'">
                </div>
                <div class="col" style="flex:1 1 160px">
                  <label>Telepon</label>
                  <input name="phone" value="'.e($u['phone'] ?? '').'">
                </div>
              </div>

              <div class="row">
                <div class="col" style="flex:1 1 220px">
                  <label>Kampus</label>
                  <select name="campus_id">
                    <option value="">-</option>';
                    foreach ($campuses as $c) {
                      $sel = ((($u['campus_id'] ?? '') === $c['id']) ? 'selected' : '');
                      echo '<option value="'.e($c['id']).'" '.$sel.'>'.e($c['name']).'</option>';
                    }
      echo '     </select>
                </div>
                <div class="col" style="flex:1 1 120px">
                  <label>Angkatan</label>
                  <input name="angkatan" value="'.e($u['angkatan'] ?? '').'">
                </div>
                <div class="col" style="flex:1 1 180px">
                  <label>Jurusan</label>
                  <input name="jurusan" value="'.e($u['jurusan'] ?? '').'">
                </div>
              </div>

              <div class="row">
                <div class="col" style="flex:1 1 100px">
                  <label>JK</label>
                  <select name="gender">
                    <option value="" '.((($u['gender'] ?? '')==='')?'selected':'').'>-</option>
                    <option value="L" '.((($u['gender'] ?? '')==='L')?'selected':'').'>L</option>
                    <option value="P" '.((($u['gender'] ?? '')==='P')?'selected':'').'>P</option>
                  </select>
                </div>
                <div class="col" style="flex:1 1 140px">
                  <label>Peran</label>
                  <select name="role">
                    <option value="user" '.((($u['role']??'')==='user')?'selected':'').'>user</option>
                    <option value="admin" '.((($u['role']??'')==='admin')?'selected':'').'>admin</option>
                  </select>
                </div>
              </div>

              <div class="mt8">
                <button class="btn-icon" title="Simpan perubahan">Simpan</button>
              </div>

              <div class="mt8">
                <label>Password baru</label>
                <input type="text" name="newpw" value="12345678" style="max-width:160px" placeholder="PW baru">
              <button class="btn-ghost" title="Reset password" type="submit" formaction="?action=user_resetpw">Reset</button>
            </div>

            </form>
          </details>
          <form method="post" action="?action=user_delete" style="display:inline" onsubmit="return confirm(\'Hapus?\')">
            <input type="hidden" name="csrf" value="'.e($csrf).'">
            <input type="hidden" name="username" value="'.$unameSafe.'">
            <button class="btn-danger" title="Hapus">Hapus</button>
          </form>
        </td>
      </tr>';
    }
    echo '</table></div>';
  }
  echo '</div>';
  layout_footer(); exit;
}

// KTB list & create (TANPA kolom Aksi)
if (strpos($action, 'ktb')===0 && !in_array($action,['ktb_members','meetings','attendance'],true)) {
  layout_header('KTB');
  flash_msg($msg);
  $csrf = csrf_token();
  $campuses = db_read('campuses');
  $users = db_read('users');

  // FORM BUAT KTB
  echo '<div class="card"><h3>Buat KTB</h3><form method="post" action="?action=ktb_add">';
  echo '<input type="hidden" name="csrf" value="'.e($csrf).'">';
  echo '<div class="row"><div class="col">
      <label>Nama KTB</label><input name="name" required></div>
      <div class="col"><label>Kampus</label><select name="campus_id" required>
        <option value="">- pilih kampus -</option>';
  foreach ($campuses as $c) echo '<option value="'.e($c['id']).'">'.e($c['name']).'</option>';
  echo '</select></div></div>';
  echo '<div class="row"><div class="col"><label>Jenis</label><select name="type">
      <option>mahasiswa</option><option>siswa</option><option>alumni</option></select></div>';

  if (is_admin()) {
    echo '<div class="col"><label>Status</label><select name="status"><option>aktif</option><option>nonaktif</option></select></div></div>';
    echo '<div class="row"><div class="col"><label>Pemimpin (username)</label><input name="leader" list="userlist" required placeholder="harus user terdaftar"></div></div>';
  } else {
    echo '<div class="col"><label>Status</label><input value="aktif" disabled class="muted"><input type="hidden" name="status" value="aktif"></div></div>';
    $me = current_user()['username'] ?? '';
    echo '<input type="hidden" name="leader" value="'.e($me).'">';
    echo '<div class="mt8 muted">Pemimpin: <b>'.e($me).'</b> (otomatis)</div>';
  }

  echo '<div class="mt16"><button class="btn-icon" title="Buat KTB">Buat KTB</button></div></form>';
  echo '<datalist id="userlist">';
  foreach ($users as $u) echo '<option value="'.e($u['username']).'">'.e(($u['name']??$u['username'])).'</option>';
  echo '</datalist></div>';

  // LIST KTB — tanpa aksi
  $ktbs = db_read('ktb_groups');
  $campMap=[]; foreach ($campuses as $c) $campMap[$c['id']]=$c['name'];
  echo '<div class="card"><h3>Daftar KTB</h3><div class="mb8">
    <a class="btn-ghost btn-icon" href="?action=export_ktb_csv" style="padding:9px 12px" title="Export CSV">Export CSV</a></div>';
  if (!$ktbs) echo '<div class="muted">Belum ada KTB.</div>';
  else {
    echo '<div class="table-wrap"><table><tr><th>Nama</th><th>Jenis</th><th>Status</th><th>Kampus</th><th>Pemimpin</th></tr>';
    foreach ($ktbs as $k) {
      echo '<tr><td>'.e($k['name']).'</td><td><span class="badge">'.e($k['type']).'</span></td>
      <td>'.($k['status']==='aktif' ? '<span class="ok">aktif</span>' : '<span class="muted">nonaktif</span>').'</td>
      <td>'.e($campMap[$k['campus_id']] ?? $k['campus_id']).'</td>
      <td>'.e($k['leader'] ?? '').'</td></tr>';
    }
    echo '</table></div>';
  }
  echo '</div>';
  layout_footer(); exit;
}

// KTB MEMBERS (aksi khusus)
if (strpos($action,'ktb_members')===0) {
  $ktb_id = $_GET['ktb_id'] ?? ($_POST['ktb_id'] ?? '');
  $ktb = get_ktb($ktb_id);
  if (!$ktb) { header('Location:?action=ktb'); exit; }
  $canManage = is_admin() || is_ktb_leader(current_user()['username'],$ktb_id);

  layout_header('Anggota KTB');
  flash_msg($msg);
  $csrf = csrf_token();

  $members = memberships_of_ktb($ktb_id);
  $users = db_read('users');
  echo '<div class="card"><h3>Anggota — '.e($ktb['name']).'</h3>';
  if ($canManage) {
    echo '<form method="post" action="?action=member_add" class="mb16">
      <input type="hidden" name="csrf" value="'.e($csrf).'">
      <input type="hidden" name="ktb_id" value="'.e($ktb_id).'">
      <label>Tambah Anggota (username)</label><input name="username" placeholder="username yang sudah terdaftar" list="userlist_add">
      <div class="mt8"><button class="btn-icon" title="Tambah anggota">Tambah</button></div></form>
      <datalist id="userlist_add">';
    foreach ($users as $u) echo '<option value="'.e($u['username']).'">'.e($u['name'] ?? $u['username']).'</option>';
    echo '</datalist>';
  } else {
    echo '<div class="muted mb8">Hanya pemimpin KTB atau admin yang bisa menambah/menghapus anggota.</div>';
  }
  if (!$members) echo '<div class="muted">Belum ada anggota.</div>';
  else {
    echo '<div class="table-wrap"><table><tr><th>Username</th><th>Peran</th><th>Sejak</th><th></th></tr>';
    foreach ($members as $m) {
      echo '<tr><td>'.e($m['username']).'</td><td>'.e($m['role']).'</td><td>'.e($m['since']).'</td><td class="nowrap">';
      if ($canManage && $m['role']!=='leader') {
        echo '<form method="post" action="?action=member_remove" onsubmit="return confirm(\'Hapus anggota?\')" style="display:inline">
        <input type="hidden" name="csrf" value="'.e($csrf).'"><input type="hidden" name="ktb_id" value="'.e($ktb_id).'">
        <input type="hidden" name="username" value="'.e($m['username']).'"><button class="btn-danger" title="Hapus anggota">Hapus</button></form>';
      } else echo '<span class="muted">-</span>';
      echo '</td></tr>';
    }
    echo '</table></div>';
  }
  echo '<div class="mt16"><a class="btn-ghost btn-icon" href="?action=meetings&ktb_id='.e($ktb_id).'" style="padding:9px 12px" title="Kelola Pertemuan">Pertemuan</a></div>';
  echo '</div>';
  layout_footer(); exit;
}

// MEETINGS (aksi khusus)
if (strpos($action,'meetings')===0) {
  $ktb_id = $_GET['ktb_id'] ?? ($_POST['ktb_id'] ?? '');
  $ktb = get_ktb($ktb_id);
  if (!$ktb) { header('Location:?action=ktb'); exit; }

  $canManage = is_admin() || is_ktb_leader(current_user()['username'],$ktb_id);
  layout_header('Pertemuan');
  flash_msg($msg);
  $csrf = csrf_token();

  echo '<div class="card"><h3>Pertemuan — '.e($ktb['name']).'</h3>';
  if ($canManage) {
    echo '<form method="post" action="?action=meeting_add" class="mb16">
      <input type="hidden" name="csrf" value="'.e($csrf).'">
      <input type="hidden" name="ktb_id" value="'.e($ktb_id).'">
      <div class="row"><div class="col"><label>Tanggal</label><input type="date" name="date" value="'.date('Y-m-d').'"></div>
      <div class="col"><label>Topik</label><input name="topic" placeholder="mis. Pemuridan 1"></div></div>
      <label>Catatan</label><textarea name="notes" rows="2" placeholder="ringkasan/pokok doa"></textarea>
      <div class="mt8"><button class="btn-icon" title="Buat Pertemuan">Buat Pertemuan</button> <span class="muted">Setelah selesai, wajib lapor (absensi + foto).</span></div>
    </form>';
  } else {
    echo '<div class="muted mb8">Hanya pemimpin KTB atau admin yang dapat mengadakan pertemuan.</div>';
  }

  $meetings = meetings_of_ktb($ktb_id);
  if (!$meetings) echo '<div class="muted">Belum ada pertemuan.</div>';
  else {
    echo '<div class="table-wrap"><table><tr><th>Tanggal</th><th>Topik</th><th>Status</th><th>Foto</th><th>Catatan</th><th class="nowrap">Aksi</th></tr>';
    foreach ($meetings as $m) {
      $photoHtml = ($m['photo'] ?? '') ? '<a href="'.e($m['photo']).'" target="_blank" title="Lihat foto">Lihat</a><br><img class="thumb" src="'.e($m['photo']).'">' : '<span class="muted">-</span>';
      echo '<tr><td>'.e($m['date']).'</td><td>'.e($m['topic']).'</td>';
      echo '<td class="status status-'.e($m['status'] ?? 'scheduled').'">'.e($m['status'] ?? 'scheduled').'</td>';
      echo '<td>'.$photoHtml.'</td><td>'.e($m['notes']).'</td><td class="nowrap">';
      if (is_admin() || is_ktb_leader(current_user()['username'],$ktb_id)) {
        echo '<a href="?action=attendance&meeting_id='.e($m['id']).'" title="Laporan">Laporan</a> | ';
        echo '<form method="post" action="?action=meeting_delete" onsubmit="return confirm(\'Hapus pertemuan?\')" style="display:inline">
          <input type="hidden" name="csrf" value="'.e($csrf).'"><input type="hidden" name="meeting_id" value="'.e($m['id']).'">
          <button class="btn-danger" title="Hapus">Hapus</button></form>';
      } else {
        echo '<span class="muted">Tidak berwenang</span>';
      }
      echo '</td></tr>';
    }
    echo '</table></div>';
  }
  echo '</div>';
  layout_footer(); exit;
}

// ATTENDANCE + FOTO
if (strpos($action,'attendance')===0) {
  $meeting_id = $_GET['meeting_id'] ?? ($_POST['meeting_id'] ?? '');
  $m = get_meeting($meeting_id);
  if (!$m) { header('Location:?action=dashboard'); exit; }
  $ktb = get_ktb($m['ktb_id']);
  $canManage = is_admin() || is_ktb_leader(current_user()['username'],$m['ktb_id']);

  layout_header('Laporan Pertemuan');
  flash_msg($msg);
  $csrf = csrf_token();
  echo '<div class="card"><h3>Laporan — '.e($ktb['name']).' ('.e($m['date']).')</h3>';
  echo '<div class="mb8">Status: <span class="status status-'.e($m['status'] ?? 'scheduled').'">'.e($m['status'] ?? 'scheduled').'</span></div>';

  $members = memberships_of_ktb($m['ktb_id']);
  $map = []; foreach (attendance_of_meeting($meeting_id) as $a) $map[strtolower($a['username'])]=$a;

  if ($canManage && $members) {
    $today = date('Y-m-d');
    $disabled = ($m['date'] > $today) ? 'disabled' : '';
    if ($disabled) {
      echo '<div class="warn mb8">Absensi & foto hanya bisa diserahkan pada tanggal pertemuan atau setelahnya.</div>';
    }
    echo '<form method="post" action="?action=attendance_set" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="'.e($csrf).'">
      <input type="hidden" name="meeting_id" value="'.e($meeting_id).'">
      <div class="table-wrap"><table><tr><th>Username</th><th>Status</th><th>Catatan</th></tr>';
    foreach ($members as $mem) {
      $u = strtolower($mem['username']); $st = $map[$u]['status'] ?? 'hadir'; $note = $map[$u]['note'] ?? '';
      echo '<tr><td>'.e($mem['username']).' '.($mem['role']==='leader'?' <span class="badge">leader</span>':'').'</td><td>
        <select name="status['.e($mem['username']).']" '.$disabled.'>
          <option '.($st==='hadir'?'selected':'').'>hadir</option>
          <option '.($st==='izin'?'selected':'').'>izin</option>
          <option '.($st==='alpha'?'selected':'').'>alpha</option>
        </select></td><td><input name="note['.e($mem['username']).']" value="'.e($note).'" '.$disabled.'></td></tr>';
    }
    echo '</table></div>';

    $photoInfo = ($m['photo'] ?? '') ? '<a href="'.e($m['photo']).'" target="_blank" title="Lihat foto">Lihat foto</a>' : '<span class="warn">Belum ada foto</span>';
    echo '<div class="mt8"><label>Upload Foto Bersama (JPG/PNG/WEBP, maks 6MB)</label>
      <input type="file" name="report_photo" accept=".jpg,.jpeg,.png,.webp" '.$disabled.'>
      <div class="mt8">Status Foto: '.$photoInfo.'</div></div>';

    echo '<div class="mt8">
      <button '.($disabled?'disabled':'').' class="btn-icon" title="Simpan Laporan">Simpan</button>
      <a class="btn-ghost btn-icon" style="padding:9px 12px" href="?action=meetings&ktb_id='.e($m['ktb_id']).'" title="Kembali">Kembali</a>
      <a class="btn-ghost btn-icon" style="padding:9px 12px" href="?action=export_attendance_csv" title="Export CSV">Export CSV</a>
    </div></form>';
    echo '<div class="muted mt8">Catatan: Jika setelah melewati tanggal pertemuan laporan (absensi + foto) belum lengkap, pertemuan otomatis dibatalkan.</div>';
  } else {
    echo '<div class="muted">Hanya pemimpin KTB atau admin yang dapat mengisi laporan.</div>';
  }
  echo '</div>';
  layout_footer(); exit;
}

// MY (user page) — Aksi dipusatkan di sini
if ($action==='my') {
  layout_header('Saya');
  $u = current_user();
  $csrf = csrf_token();
  $roles = user_ktb_roles($u['username']);
  $allKtb = db_read('ktb_groups');
  $campuses = db_read('campuses'); $campMap = []; foreach($campuses as $c) $campMap[$c['id']]=$c['name'];
  $users = db_read('users');

  echo '<div class="card"><h3>Profil</h3><div>Username: <b>'.e($u['username']).'</b> &nbsp; | &nbsp; Peran sistem: <span class="badge">'.e($u['role']).'</span></div>';
  echo '<div class="muted mt8">Aksi pengelolaan KTB dipusatkan di halaman ini.</div></div>';

  // KTB yang user terlibat
  echo '<div class="card"><h3>Keterlibatan KTB</h3>';
  if (!$roles) {
    echo '<div class="muted">Belum terdaftar pada KTB manapun.</div>';
  } else {
    echo '<div class="table-wrap"><table><tr><th>KTB</th><th>Peran</th><th>Kampus</th><th>Aksi</th></tr>';
    foreach ($roles as $r) {
      $k = null;
      foreach ($allKtb as $kk) { if ($kk['id']===$r['ktb_id']) { $k=$kk; break; } }
      if (!$k) continue;

      $canManage = is_admin() || is_ktb_leader($u['username'],$k['id']);

      echo '<tr><td>'.e($k['name']).'</td><td>'.e($r['role']).'</td><td>'.e($campMap[$k['campus_id']] ?? $k['campus_id']).'</td><td class="nowrap">';
      echo '<a href="?action=ktb_members&ktb_id='.e($k['id']).'">Anggota</a> | <a href="?action=meetings&ktb_id='.e($k['id']).'">Pertemuan</a>';
      if ($canManage) {
        // Form edit di details
        echo ' | <details style="display:inline-block"><summary>Edit</summary>
          <form method="post" action="?action=ktb_update" class="mt8" style="min-width:280px">
            <input type="hidden" name="csrf" value="'.e($csrf).'">
            <input type="hidden" name="id" value="'.e($k['id']).'">
            <label>Nama</label><input name="name" value="'.e($k['name']).'" required>
            <label>Kampus</label><select name="campus_id">';
            foreach ($campuses as $c) echo '<option value="'.e($c['id']).'" '.(($k['campus_id']===$c['id'])?'selected':'').'>'.e($c['name']).'</option>';
        echo '</select>
            <label>Jenis</label><select name="type">';
            foreach (['siswa','mahasiswa','alumni'] as $tp) echo '<option '.(($k['type']===$tp)?'selected':'').'>'.$tp.'</option>';
        echo '</select>
            <label>Status</label><select name="status"><option '.(($k['status']==='aktif')?'selected':'').'>aktif</option><option '.(($k['status']==='nonaktif')?'selected':'').'>nonaktif</option></select>
            <label>Pemimpin (username)</label><input name="leader" value="'.e($k['leader'] ?? '').'" list="userlist_my" required>
            <div class="mt8"><button class="btn-icon" title="Simpan">Simpan</button></div>
          </form></details>';
        if (is_admin()) {
          echo ' | <form method="post" action="?action=ktb_delete" onsubmit="return confirm(\'Hapus KTB?\')" style="display:inline">
            <input type="hidden" name="csrf" value="'.e($csrf).'">
            <input type="hidden" name="id" value="'.e($k['id']).'">
            <button class="btn-danger" title="Hapus KTB">Hapus</button></form>';
        }
      }
      echo '</td></tr>';
    }
    echo '</table></div>';
    // datalist user untuk edit leader
    echo '<datalist id="userlist_my">';
    foreach ($users as $uu) echo '<option value="'.e($uu['username']).'">'.e($uu['name'] ?? $uu['username']).'</option>';
    echo '</datalist>';
  }
  echo '</div>';

  // Jika admin, tampilkan semua KTB dengan aksi
  if (is_admin()) {
    echo '<div class="card"><h3>Semua KTB (Admin)</h3>';
    if (!$allKtb) {
      echo '<div class="muted">Belum ada KTB.</div>';
    } else {
      echo '<div class="table-wrap"><table><tr><th>Nama</th><th>Jenis</th><th>Status</th><th>Kampus</th><th>Pemimpin</th><th>Aksi</th></tr>';
      foreach ($allKtb as $k) {
        echo '<tr><td>'.e($k['name']).'</td><td><span class="badge">'.e($k['type']).'</span></td>
        <td>'.($k['status']==='aktif' ? '<span class="ok">aktif</span>' : '<span class="muted">nonaktif</span>').'</td>
        <td>'.e($campMap[$k['campus_id']] ?? $k['campus_id']).'</td>
        <td>'.e($k['leader'] ?? '').'</td><td class="nowrap">';
        echo '<a href="?action=ktb_members&ktb_id='.e($k['id']).'">Anggota</a> | <a href="?action=meetings&ktb_id='.e($k['id']).'">Pertemuan</a> | ';
        echo '<details style="display:inline-block"><summary>Edit</summary>
          <form method="post" action="?action=ktb_update" class="mt8" style="min-width:280px">
            <input type="hidden" name="csrf" value="'.e($csrf).'">
            <input type="hidden" name="id" value="'.e($k['id']).'">
            <label>Nama</label><input name="name" value="'.e($k['name']).'" required>
            <label>Kampus</label><select name="campus_id">';
            foreach ($campuses as $c) echo '<option value="'.e($c['id']).'" '.(($k['campus_id']===$c['id'])?'selected':'').'>'.e($c['name']).'</option>';
        echo '</select>
            <label>Jenis</label><select name="type">';
            foreach (['siswa','mahasiswa','alumni'] as $tp) echo '<option '.(($k['type']===$tp)?'selected':'').'>'.$tp.'</option>';
        echo '</select>
            <label>Status</label><select name="status"><option '.(($k['status']==='aktif')?'selected':'').'>aktif</option><option '.(($k['status']==='nonaktif')?'selected':'').'>nonaktif</option></select>
            <label>Pemimpin (username)</label><input name="leader" value="'.e($k['leader'] ?? '').'" list="userlist_admin" required>
            <div class="mt8"><button class="btn-icon" title="Simpan">Simpan</button></div>
          </form></details>
          | <form method="post" action="?action=ktb_delete" onsubmit="return confirm(\'Hapus KTB?\')" style="display:inline">
            <input type="hidden" name="csrf" value="'.e($csrf).'">
            <input type="hidden" name="id" value="'.e($k['id']).'">
            <button class="btn-danger" title="Hapus KTB">Hapus</button></form>';
        echo '</td></tr>';
      }
      echo '</table></div>';
      echo '<datalist id="userlist_admin">';
      foreach ($users as $uu) echo '<option value="'.e($uu['username']).'">'.e($uu['name'] ?? $uu['username']).'</option>';
      echo '</datalist>';
    }
    echo '</div>';
  }

  layout_footer(); exit;
}

// default
header('Location:?action=dashboard'); exit;
