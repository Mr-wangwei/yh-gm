# yh-gm
银海医保系统SM2签名 SM4加密解密
该项目需要安装 php openssl(1.1.1以上) 扩展 或者 gmssl 扩展

SM4 加解密采用php openssl(1.1.1以上) 扩展 或者 gmssl 扩展

SM2 签名 使用 gmp 扩展 计算消息摘要SM3 使用 openssl 或者 gmssl
### 安装
```shell
composer require yh/gm
```

### SM2
```php
// 签名
$sign = \Gm\Helper\SM2::sign($message, $prvKey, '1234567812345678');
// 验签
$isV = \Gm\Helper\SM2::verify($message, $sign, $platformPubKey, '1234567812345678');

```

### SM4
```php
// 加密
$encrypt = \Gm\Helper\SM4::encrypt($appId, $key, $message);

// 解密
$decrypt = \Gm\Helper\SM4::decrypt($appId, $key, $encrypt);

```