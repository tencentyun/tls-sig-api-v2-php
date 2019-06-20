## 说明
此项目为 tls-sig-api-v2 版本 php 实现，之前非对称密钥无法使用此版本 api，如需使用请查看[这里](https://github.com/tencentyun/tls-sig-api-php)。

## 集成
使用 composer 或者源码集成均可。

### composer 集成
``` json
{
  "require": {
    "tencent/tls-sig-api-v2": "1.0"
  }
}
```

### 源码集成
将 `TLSSigAPIv2.php` 下载至工程中即可。

## 使用
``` php
<?php

require 'vendor/autoload.php'
// require_once "../src/TLSSigAPIv2.php"; // 源码集成使用相对路径 

$api = new \Tencent\TLSSigAPIv2(1400000000, '5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e');
$sig = $api->genSig('xiaojun');
echo $sig . "\n";
```
