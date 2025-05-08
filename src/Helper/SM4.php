<?php

namespace Gm\Helper;

use Gm\Core\GmsslSM4;
use Gm\Core\OpensslSM4;

class SM4
{
    protected $sm4;
    public function __construct()
    {
        if (extension_loaded('gmssl')) {
            $this->sm4 = new GmsslSM4();
        } else {
            $this->sm4 = new OpensslSM4();
        }
    }

    public static function make(): static
    {
        return new static;
    }

    /**
     * @param string $appId
     * @param string $key
     * @param string $message
     * @return string 加密字符串
     * @throws \Exception
     */
    public static function encrypt(string $appId, string $key, string $message): string
    {
        // 用appId加密appSecret获取新密钥
        $appSecretEncData = static::make()->sm4->encrypt(substr($appId, 0, 16), $key);

        // 新密钥串
        $secKey = substr(strtoupper(bin2hex($appSecretEncData)), 0, 16);

        // 加密数据
        return strtoupper(bin2hex(static::make()->sm4->encrypt($secKey, $message)));
    }

    /**
     * @param string $appId
     * @param string $key
     * @param string $message
     * @return string
     * @throws \Exception
     */
    public static function decrypt(string $appId, string $key, string $message): string
    {
        // 生产解密key
        $appSecretEncDataDecode = static::make()->sm4->encrypt(substr($appId, 0, 16), $key);
        $secKeyDecode = substr(strtoupper(bin2hex($appSecretEncDataDecode)), 0, 16);

        return static::make()->sm4->decrypt($secKeyDecode, hex2bin($message));
    }
}