<?php
/**
 * SM2 曲线类
 */

namespace Gm\Core;

use Gm\Core\Trait\SM3Trait;

class SM2Curve
{
    use SM3Trait;

    public $a; // 曲线参数 a
    public $b; // 曲线参数 b
    public $p; // 素数 p
    public $n; // 基点 G 的阶
    public $gx; // 基点 G 的 x 坐标
    public $gy; // 基点 G 的 y 坐标

    /**
     * @throws \Exception
     */
    public function __construct()
    {
        // 设置 SM2 曲线参数 (与 Java 代码中使用的相同)
        $this->a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
        $this->b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
        $this->p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
        $this->n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);
        $this->gx = new BigInteger('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16);
        $this->gy = new BigInteger('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16);
    }

    /**
     * 曲线点加法: P + Q
     * @param BigInteger $x1 P点的x坐标
     * @param BigInteger $y1 P点的y坐标
     * @param BigInteger $x2 Q点的x坐标
     * @param BigInteger $y2 Q点的y坐标
     * @return array 结果点的坐标 [x3, y3]
     */
    public function addPoints($x1, $y1, $x2, $y2): array
    {
        // 如果其中一点是无穷远点
        if ($x1 === null || $y1 === null) {
            return [$x2, $y2];
        }
        if ($x2 === null || $y2 === null) {
            return [$x1, $y1];
        }

        // 如果P = -Q，返回无穷远点
        if ($x1->equals($x2) && $y1->equals($this->p->subtract($y2))) {
            return [null, null];
        }

        // 计算斜率λ
        $lambda = null;
        if ($x1->equals($x2) && $y1->equals($y2)) {
            // 点倍乘的情况：λ = (3*x1^2 + a) / (2*y1)
            $temp1 = $x1->multiply($x1)->multiply(new BigInteger('3'))->add($this->a);
            $temp2 = $y1->multiply(new BigInteger('2'));
            $lambda = $temp1->multiply($temp2->modInverse($this->p))->mod($this->p);
        } else {
            // 不同点相加的情况：λ = (y2 - y1) / (x2 - x1)
            $temp1 = $y2->subtract($y1);
            $temp2 = $x2->subtract($x1);
            $lambda = $temp1->multiply($temp2->modInverse($this->p))->mod($this->p);
        }

        // 计算结果点坐标
        // x3 = λ^2 - x1 - x2
        $x3 = $lambda->multiply($lambda)->subtract($x1)->subtract($x2)->mod($this->p);
        // y3 = λ(x1 - x3) - y1
        $y3 = $lambda->multiply($x1->subtract($x3))->subtract($y1)->mod($this->p);

        return [$x3, $y3];
    }

    /**
     * 标量乘法：k * G，乘以基点
     * @param BigInteger $k 标量
     * @return array 结果点的坐标 [x, y]
     */
    public function multiplyG($k): array
    {
        return $this->multiplyPoint($this->gx, $this->gy, $k);
    }

    /**
     * 标量乘法：k * P，乘以任意点
     * @param BigInteger $x P点的x坐标
     * @param BigInteger $y P点的y坐标
     * @param BigInteger $k 标量
     * @return array 结果点的坐标 [x, y]
     */
    public function multiplyPoint($x, $y, $k): array
    {
        // 使用"二进制扩展"（双倍加）算法
        if ($k->equals(BigInteger::zero())) {
            return [null, null]; // 无穷远点
        }

        if ($k->equals(BigInteger::one())) {
            return [$x, $y];
        }

        $result = [null, null]; // 初始为无穷远点
        $addend = [$x, $y];

        $kBin = $k->toBits();

        // 从最高位开始处理
        for ($i = 0; $i < strlen($kBin); $i++) {
            // 每次迭代都倍乘结果点
            $result = $this->addPoints($result[0], $result[1], $result[0], $result[1]);

            // 如果当前位为1，加上P点
            if (substr($kBin, $i, 1) == '1') {
                $result = $this->addPoints($result[0], $result[1], $addend[0], $addend[1]);
            }
        }

        return $result;
    }

    /**
     * 计算SM2签名中使用的Z值
     * @param BigInteger $publicKeyX 公钥X坐标
     * @param BigInteger $publicKeyY 公钥Y坐标
     * @param string $userId 用户ID
     * @return string Z值
     * @throws \Exception
     */
    public function calculateZ(BigInteger $publicKeyX, BigInteger $publicKeyY, string $userId = '1234567812345678'): string
    {
        // 计算ENTLA（userId比特长度，2字节）
        $entla = strlen($userId) * 8;
        $entlaBytes = pack('n', $entla); // 'n'表示16位网络序（大端序）
        // 转换曲线参数为字节串
        $aBytes = $this->bigIntegerToBytes($this->a, 32);
        $bBytes = $this->bigIntegerToBytes($this->b, 32);
        $gxBytes = $this->bigIntegerToBytes($this->gx, 32);
        $gyBytes = $this->bigIntegerToBytes($this->gy, 32);
        $xaBytes = $this->bigIntegerToBytes($publicKeyX, 32);
        $yaBytes = $this->bigIntegerToBytes($publicKeyY, 32);

        // 创建Z预处理数据
        $zData = $entlaBytes . $userId . $aBytes . $bBytes . $gxBytes . $gyBytes . $xaBytes . $yaBytes;

        // 使用SM3哈希函数计算Z值
        return $this->sm3Hash($zData);
    }

    /**
     * 将BigInteger转换为固定长度的字节串
     * @param BigInteger $bigInt 大整数
     * @param int $length 字节长度
     * @return string 字节串
     */
    private function bigIntegerToBytes($bigInt, $length)
    {
        $hex = $bigInt->toHex();
        $hex = str_pad($hex, $length * 2, '0', STR_PAD_LEFT);
        return hex2bin($hex);
    }
}