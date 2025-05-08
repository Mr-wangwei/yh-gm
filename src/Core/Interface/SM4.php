<?php

namespace Gm\Core\Interface;

interface SM4
{
    /**
     * SM4加密函数
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encrypt(string $key, string $data): string;

    /**
     * SM4解密函数
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decrypt(string $key, string $data): string;


}