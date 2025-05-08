<?php

namespace Gm\Core\Trait;

trait SM3Trait
{
    /**
     * SM3 哈希函数
     * @param string $data 待哈希数据
     * @return string 哈希结果 (32 字节)
     * @throws \Exception
     */
    public function sm3Hash(string $data): string
    {
        // 实现 SM3 哈希算法
        if (extension_loaded('gmssl')) {
            return bin2hex(gmssl_sm3($data));
        }

        // 这里可以使用已有的 SM3 PHP 实现或外部库
        if (in_array('sm3', openssl_get_md_methods())) {
            return bin2hex(openssl_digest($data, 'sm3', true));
        }

        throw new \Exception('SM3 hash function is not available.');

    }
}