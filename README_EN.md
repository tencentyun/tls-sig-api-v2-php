## Note
This project is the php implementation of tls-sig-api-v2. Previous asymmetric keys cannot use APIs of this version. To enable them to use APIs of this version,[see here](https://github.com/tencentyun/tls-sig-api-php)。

## integration
You can use composer or source code integration.

### composer integration
``` json
{
  "require": {
    "tencent/tls-sig-api-v2": "1.0"
  }
}
```

### source code integration
Download `TLSSigAPIv2.php` to the project.

## use
``` php
<?php

require 'vendor/autoload.php'
// require_once "../src/TLSSigAPIv2.php"; // 源码集成使用相对路径 

$api = new \Tencent\TLSSigAPIv2(1400000000, '5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e');
$sig = $api->genUserSig('xiaojun');
echo $sig . "\n";
```
