<?php

require_once "../src/TLSSigAPIv2.php";

$api = new \Tencent\TLSSigAPIv2(1400000000, '5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e');
$sig = $api->genSig('xiaojun');
echo $sig . "\n";
$init_time = 0;
$expire = 0;
$err_msg = '';
$ret = $api->verifySig($sig, 'xiaojun', $init_time, $expire, $err_msg);
if (!$ret) {
    echo $err_msg . "\n";
} else {
    echo "verify ok expire $expire init time $init_time\n";
}
$userbuf = '';
$ret = $api->verifySigWithUserBuf($sig, 'xiaojun', $init_time, $expire,$userbuf, $err_msg);
if (!$ret) {
    echo $err_msg . "\n";
} else {
    echo "verify ok expire $expire init time $init_time userbuf $userbuf\n";
}

$sig = $api->genSigWithUserBuf('xiaojun', 86400*180, 'abc');
echo $sig . "\n";
$init_time = 0;
$expire = 0;
$err_msg = '';
$ret = $api->verifySig($sig, 'xiaojun', $init_time, $expire, $err_msg);
if (!$ret) {
    echo $err_msg . "\n";
} else {
    echo "verify ok expire $expire init time $init_time\n";
}
$userbuf = '';
$ret = $api->verifySigWithUserBuf($sig, 'xiaojun', $init_time, $expire,$userbuf, $err_msg);
if (!$ret) {
    echo $err_msg . "\n";
} else {
    echo "verify ok expire $expire init time $init_time userbuf $userbuf\n";
}
