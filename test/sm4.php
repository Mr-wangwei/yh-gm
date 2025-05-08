<?php

require_once  __DIR__ . '/../vendor/autoload.php';

$appId = '0F0822652EB7CB91A644E638FBE9941E';
$key = '30BFE2B0C715E516E5EDF21E289DA826';
$message = 'a';

$encrypt = \Gm\Helper\SM4::encrypt($appId, $key, $message);

var_dump($encrypt);

// 解密
$decrypt = \Gm\Helper\SM4::decrypt($appId, $key, $encrypt);

var_dump($decrypt);