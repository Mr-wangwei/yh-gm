<?php

namespace Gm\Helper;

use Gm\Core\SM2 as SM2Base;

class SM2
{
    public SM2Base $sm2;
    public function __construct()
    {
        $this->sm2 = new SM2Base();
    }

    public static function make(): static
    {
        return new static;
    }

    /**
     * @param string $message
     * @param string $userId
     * @param string $prvKey
     * @return string 加密字符串
     * @throws \Exception
     */
    public static function sign(string $message, string $prvKey, string $userId = '1234567812345678'): string
    {
        return self::make()->sm2->sign($message, $prvKey, $userId);
    }

    /**
     * @param string $message
     * @param string $userid
     * @param string $pubKey
     * @return bool
     * @throws \Exception
     */
    public static function verify(string $message, string $sign, string $pubKey, string $userid = '1234567812345678'): bool
    {
        return self::make()->sm2->verify($message, $sign, $pubKey, $userid);
    }
}