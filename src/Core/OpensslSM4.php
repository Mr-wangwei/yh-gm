<?php

namespace Gm\Core;

use Gm\Core\Interface\SM4;

class OpensslSM4 implements SM4
{
    /**
     * 加密
     * @param string $key
     * @param string $data
     * @return string 加密后的数据
     */
    public function encrypt(string $key, string $data): string
    {
        if (strlen($key) !== 16) {
            throw new \Exception('错误的密钥长度');
        }

        $cipher = 'SM4-ECB';
        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;

        $paddedData = $this->pkcs7Pad($data, 16);
        $encrypted = openssl_encrypt($paddedData, $cipher, $key, $options);

        if ($encrypted === false) {
            throw new \Exception('加密失败');
        }

        return $encrypted;
    }

    /**
     * 解密
     * @param string $key
     * @param string $data
     * @return string 解密后的数据
     */
    public function decrypt(string $key, string $data): string
    {
        if (strlen($key) !== 16) {
            throw new \Exception('错误的密钥长度');
        }

        if (strlen($data) % 16 !== 0) {
            throw new \Exception('错误的数据长度');
        }

        $cipher = 'SM4-ECB';
        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;

        $decrypted = openssl_decrypt($data, $cipher, $key, $options);

        if ($decrypted === false) {
            throw new \Exception('解密失败');
        }

        return $this->pkcs7Unpad($decrypted);
    }

    protected function pkcs7Pad(string $data, int $blockSize) : string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($pad), $pad);
    }

    protected function pkcs7Unpad(string $data) : string
    {
        $pad = ord($data[strlen($data) - 1]);
        if ($pad > strlen($data)) {
            throw new \Exception('无效的填充');
        }
        return substr($data, 0, -$pad);
    }
}