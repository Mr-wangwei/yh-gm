<?php

namespace Gm\Core;

use Gm\Core\Interface\SM4;

class GmsslSM4 implements SM4
{
    /**
     * 加密
     * @param string $key
     * @param string $data
     * @return string 加密后的数据
     * @throws \Exception
     */
    public function encrypt(string $key, string $data): string
    {
        if (strlen($key) !== GMSSL_SM4_KEY_SIZE) {
            throw new \Exception('错误的密钥长度');
        }

        $paddedData = $this->pkcs7Pad($data, GMSSL_SM4_BLOCK_SIZE);

        // 使用GmSSL提供的SM4 ECB模式加密
        $encrypted = '';
        for ($i = 0; $i < strlen($paddedData); $i += GMSSL_SM4_BLOCK_SIZE) {
            $block = substr($paddedData, $i, GMSSL_SM4_BLOCK_SIZE);
            $encrypted .= gmssl_sm4_encrypt($key, $block);
        }

        return $encrypted;
    }

    /**
     * 解密
     * @param string $key
     * @param string $data
     * @return string 解密后的数据
     * @throws \Exception
     */
    public function decrypt(string $key, string $data): string
    {
        if (strlen($key) !== GMSSL_SM4_KEY_SIZE) {
            throw new \Exception('错误的密钥长度');
        }

        if (strlen($data) % GMSSL_SM4_BLOCK_SIZE !== 0) {
            throw new \Exception('错误的数据长度');
        }

        // 使用GmSSL提供的SM4 ECB模式解密
        $decrypted = '';
        for ($i = 0; $i < strlen($data); $i += GMSSL_SM4_BLOCK_SIZE) {
            $block = substr($data, $i, GMSSL_SM4_BLOCK_SIZE);
            $decrypted .= gmssl_sm4_decrypt($key, $block);
        }

        return $this->pkcs7Unpad($decrypted);
    }

    protected function pkcs7Pad(string $data, int $blockSize): string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($pad), $pad);
    }

    /**
     * PKCS7去填充
     * @param string $data 待去填充数据
     * @return string 去填充后的数据
     * @throws \Exception
     */
    protected function pkcs7Unpad(string $data): string
    {
        $pad = ord($data[strlen($data) - 1]);
        if ($pad > strlen($data)) {
            throw new \Exception('无效的填充');
        }
        return substr($data, 0, -$pad);
    }
}