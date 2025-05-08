<?php

namespace Gm\Core;

/**
 * 大整数类 (使用 GMP 或 BCMath 扩展)
 * 为 SM2 加密算法提供必要的大整数运算
 */
class BigInteger
{
    public $value;

    /**
     * 构造函数
     * @param string|int $value 值
     * @param int $base 基数 (默认为 10)
     * @throws \Exception
     */
    public function __construct(string|int $value, int $base = 10)
    {
        if (function_exists('gmp_init')) {
            // 使用 GMP 扩展
            $this->value = gmp_init(strval($value), $base);
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 扩展
            if ($base == 10) {
                $this->value = strval($value);
            } else {
                // 将其他进制转为十进制
                $this->value = $this->baseConvert($value, $base, 10);
            }
        } else {
            throw new \Exception("需要 GMP 或 BCMath 扩展支持！");
        }
    }

    /**
     * 将一个字符串从任意进制转换为任意进制
     * @param string $value 要转换的值
     * @param int $fromBase 源进制
     * @param int $toBase 目标进制
     * @return string 转换后的值
     */
    private function baseConvert($value, $fromBase, $toBase)
    {
        if ($fromBase == 10) {
            return base_convert($value, $fromBase, $toBase);
        }

        // 先转为10进制
        $decimal = base_convert($value, $fromBase, 10);

        // 再转为目标进制
        return base_convert($decimal, 10, $toBase);
    }

    /**
     * 静态方法: 返回零值
     * @return BigInteger 值为0的BigInteger对象
     */
    public static function zero()
    {
        return new self('0');
    }

    /**
     * 静态方法: 返回一值
     * @return BigInteger 值为1的BigInteger对象
     */
    public static function one()
    {
        return new self('1');
    }

    /**
     * 转成十六进制字符串
     * @return string 十六进制表示
     */
    public function toHex()
    {
        if (function_exists('gmp_strval')) {
            return gmp_strval($this->value, 16);
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 实现
            $hex = "";
            $decimal = $this->value;

            while (bccomp($decimal, '0') > 0) {
                $remainder = bcmod($decimal, '16');
                $hex = dechex(intval($remainder)) . $hex;
                $decimal = bcdiv($decimal, '16', 0);
            }

            return $hex == "" ? "0" : $hex;
        }
    }

    /**
     * 转换为二进制表示
     * @return string 二进制表示
     */
    public function toBits()
    {
        if (function_exists('gmp_strval')) {
            // 使用 GMP 扩展
            $bin = gmp_strval($this->value, 2);
            return $bin;
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 实现
            $hex = $this->toHex();
            $bits = "";

            for ($i = 0; $i < strlen($hex); $i++) {
                $chunk = hexdec($hex[$i]);
                $binChunk = str_pad(decbin($chunk), 4, '0', STR_PAD_LEFT);
                $bits .= $binChunk;
            }

            // 去除前导零
            $bits = ltrim($bits, '0');

            // 确保至少有一位
            if ($bits === "") {
                $bits = "0";
            }

            return $bits;
        }
    }

    /**
     * 加法
     * @param BigInteger $b 加数
     * @return BigInteger 和
     */
    public function add($b)
    {
        if ($b === null) {
            return clone $this;
        }

        if (function_exists('gmp_add')) {
            // 使用 GMP 扩展
            $result = gmp_add($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 实现
            $result = bcadd($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 减法
     * @param BigInteger $b 减数
     * @return BigInteger 差
     */
    public function subtract($b)
    {
        if ($b === null) {
            return clone $this;
        }

        if (function_exists('gmp_sub')) {
            // 使用 GMP 扩展
            $result = gmp_sub($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcsub')) {
            // 使用 BCMath 实现
            $result = bcsub($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 乘法
     * @param BigInteger $b 乘数
     * @return BigInteger 积
     */
    public function multiply($b)
    {
        if ($b === null) {
            return self::zero();
        }

        if (function_exists('gmp_mul')) {
            // 使用 GMP 扩展
            $result = gmp_mul($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcmul')) {
            // 使用 BCMath 实现
            $result = bcmul($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 模运算
     * @param BigInteger $m 模数
     * @return BigInteger 模
     */
    public function mod($m)
    {
        if ($m === null) {
            return clone $this;
        }

        if (function_exists('gmp_mod')) {
            // 使用 GMP 扩展
            $result = gmp_mod($this->value, $m->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcmod')) {
            // 使用 BCMath 实现
            $result = bcmod($this->value, $m->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 模逆运算
     * @param BigInteger $m 模数
     * @return BigInteger 模逆
     */
    public function modInverse($m)
    {
        if ($m === null) {
            throw new Exception("模数不能为空");
        }

        if (function_exists('gmp_invert')) {
            // 使用 GMP 扩展
            $result = gmp_invert($this->value, $m->value);
            if ($result === false) {
                throw new Exception("模逆不存在");
            }
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcadd')) {
            // 使用扩展欧几里得算法
            $a = $this->value;
            $n = $m->value;

            // 扩展欧几里得算法
            $t = '0';
            $newt = '1';
            $r = $n;
            $newr = $a;

            while (bccomp($newr, '0') != 0) {
                $quotient = bcdiv($r, $newr, 0);

                $temp = $newt;
                $newt = bcsub($t, bcmul($quotient, $newt));
                $t = $temp;

                $temp = $newr;
                $newr = bcsub($r, bcmul($quotient, $newr));
                $r = $temp;
            }

            if (bccomp($r, '1') > 0) {
                throw new Exception("模逆不存在");
            }

            if (bccomp($t, '0') < 0) {
                $t = bcadd($t, $n);
            }

            $obj = new self('0');
            $obj->value = $t;
            return $obj;
        }
    }

    /**
     * 比较
     * @param BigInteger $b 比较值
     * @return int 比较结果，小于返回-1，等于返回0，大于返回1
     */
    public function compare($b)
    {
        if ($b === null) {
            return 1; // 任何数都大于 null
        }

        if (function_exists('gmp_cmp')) {
            // 使用 GMP 扩展
            return gmp_cmp($this->value, $b->value);
        } else if (function_exists('bccomp')) {
            // 使用 BCMath 实现
            return bccomp($this->value, $b->value);
        }
    }

    /**
     * 相等性检查
     * @param BigInteger $b 比较值
     * @return bool 是否相等
     */
    public function equals($b)
    {
        if ($b === null) {
            return false;
        }

        return $this->compare($b) === 0;
    }

    /**
     * 幂运算
     * @param int $exponent 指数
     * @return BigInteger 结果
     */
    public function pow($exponent)
    {
        if (function_exists('gmp_pow')) {
            // 使用 GMP 扩展
            $result = gmp_pow($this->value, $exponent);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcpow')) {
            // 使用 BCMath 实现
            $result = bcpow($this->value, strval($exponent));
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 模幂运算
     * @param BigInteger $exponent 指数
     * @param BigInteger $modulus 模数
     * @return BigInteger 结果
     */
    public function modPow($exponent, $modulus)
    {
        if (function_exists('gmp_powm')) {
            // 使用 GMP 扩展
            $result = gmp_powm($this->value, $exponent->value, $modulus->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcpowmod')) {
            // 使用 BCMath 实现
            $result = bcpowmod($this->value, $exponent->value, $modulus->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 克隆方法
     * @return BigInteger 克隆的对象
     */
    public function __clone()
    {
        $new = new self('0');
        if (function_exists('gmp_init')) {
            $new->value = gmp_init(gmp_strval($this->value));
        } else {
            $new->value = $this->value;
        }
        return $new;
    }

    /**
     * 转为字符串
     * @return string 十进制字符串表示
     */
    public function __toString()
    {
        if (function_exists('gmp_strval')) {
            return gmp_strval($this->value);
        } else {
            return $this->value;
        }
    }

    /**
     * 取绝对值
     * @return BigInteger 绝对值
     */
    public function abs()
    {
        if (function_exists('gmp_abs')) {
            $result = gmp_abs($this->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 实现
            $result = (bccomp($this->value, '0') < 0) ? substr($this->value, 1) : $this->value;
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }
    }

    /**
     * 取相反数
     * @return BigInteger 相反数
     */
    public function negate(): BigInteger
    {
        if (function_exists('gmp_neg')) {
            $result = gmp_neg($this->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        }

        // 使用 BCMath 实现
        $result = (bccomp($this->value, '0') == 0) ? '0' : ((bccomp($this->value, '0') < 0) ? substr($this->value, 1) : '-' . $this->value);
        $obj = new self('0');
        $obj->value = $result;
        return $obj;
    }

    /**
     * 使用欧几里德算法计算最大公因数
     * @param BigInteger $b 另一个数
     * @return BigInteger 最大公因数
     */
    public function gcd($b)
    {
        if (function_exists('gmp_gcd')) {
            $result = gmp_gcd($this->value, $b->value);
            $obj = new self('0');
            $obj->value = $result;
            return $obj;
        } else if (function_exists('bcadd')) {
            // 使用 BCMath 实现欧几里德算法
            $a = $this->abs()->value;
            $b = $b->abs()->value;

            while (bccomp($b, '0') != 0) {
                $temp = $b;
                $b = bcmod($a, $b);
                $a = $temp;
            }

            $obj = new self('0');
            $obj->value = $a;
            return $obj;
        }
    }
}