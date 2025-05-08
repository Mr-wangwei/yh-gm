<?php

namespace Gm\Core;

use Gm\Core\Trait\SM3Trait;

class SM2
{
    use SM3Trait;

    /**
     * SM2 签名实现
     * @param string $message 待签名消息
     * @param string $base64PrivateKey Base64 编码的 Java 格式 SM2 私钥
     * @param string $userId 用户 ID
     * @return string Base64 编码的签名结果
     * @throws \Exception
     */
    public function sign(string $message, string $base64PrivateKey, string $userId = '1234567812345678'): string
    {
        // 解码 Base64 私钥
        $privateKeyBin = base64_decode($base64PrivateKey);

        // 从二进制数据中提取 d 值（大整数）
        $d = new BigInteger(bin2hex($privateKeyBin), 16);
        // SM2 曲线参数 (与 Java 代码中使用的相同)
        $curve = new SM2Curve();

        list($publicKeyX, $publicKeyY) = $curve->multiplyG($d);

        // 计算 Z 值 (与 Java 中的 SM3 摘要相同)
        $z = $curve->calculateZ($publicKeyX, $publicKeyY, $userId);

        // 计算消息摘要 (SM3)
        $digest = $this->sm3Hash(hex2bin($z . bin2hex($message)));

        // 签名过程
        $e = new BigInteger($digest, 16);
        // 生成随机数 k
        $k = $this->generateRandomK($curve->n); // n 是曲线的阶
//        $k = new BigInteger('10000');
        // 计算点 (x1, y1) = k * G
        list($x1, $y1) = $curve->multiplyG($k);
        // 计算 r = (e + x1) mod n
        $r = $e->add($x1)->mod($curve->n);

        // 检查 r 是否为 0 或 r + k 是否等于 n
        if ($r->equals(BigInteger::zero()) || $r->add($k)->equals($curve->n)) {
            // 如果是，重新生成 k
            return $this->sign($message, $base64PrivateKey, $userId);
        }

        // 计算 s = ((1 + d)^(-1) * (k - r * d)) mod n
        $s = $d->add(BigInteger::one())
            ->modInverse($curve->n)
            ->multiply($k->subtract($r->multiply($d)))
            ->mod($curve->n);

        // 检查 s 是否为 0
        if ($s->equals(BigInteger::zero())) {
            // 如果是，重新生成 k
            return $this->sign($message, $base64PrivateKey, $userId);
        }

        // 格式化签名结果 (r, s)
        $rBin = hex2bin(str_pad($r->toHex(), 64, '0', STR_PAD_LEFT));
        $sBin = hex2bin(str_pad($s->toHex(), 64, '0', STR_PAD_LEFT));

        // 合并 r 和 s
        $signature = $rBin . $sBin;
        // 返回 Base64 编码的签名
        return base64_encode($signature);
    }

    /**
     * SM2 验签实现
     * @param string $message 原始消息
     * @param string $userId 用户 ID
     * @param string $base64Signature Base64 编码的签名
     * @param string $base64PublicKey Base64 编码的公钥
     * @return bool 验证结果
     * @throws \Exception
     */
    public function verify(string $message, string $base64Signature, string $base64PublicKey, string $userId = '1234567812345678'): bool
    {
        // 解码 Base64 签名和公钥
        $signatureBin = base64_decode($base64Signature);
        $publicKeyBin = base64_decode($base64PublicKey);

        if (strlen($base64Signature) < 64) {
            return false;
        }

        // 提取 r 和 s 值
        $r = new BigInteger(bin2hex(substr($signatureBin, 0, 32)), 16);
        $s = new BigInteger(bin2hex(substr($signatureBin, 32, 32)), 16);

        // 提取公钥坐标 (x, y)
        // 注意: 这里假设 Java 公钥格式是特定的，需根据实际格式调整
        // 通常公钥是 04 || x || y 格式
        if (strlen($publicKeyBin) >= 65 && $publicKeyBin[0] === "\x04") {
            $x = new BigInteger(bin2hex(substr($publicKeyBin, 1, 32)), 16);
            $y = new BigInteger(bin2hex(substr($publicKeyBin, 33, 32)), 16);
        } else {
            // 处理压缩格式的公钥或其他格式
            throw new \Exception("不支持的公钥格式");
        }

        // SM2 曲线参数
        $curve = new SM2Curve();

        // 验证 r 和 s 是否在 [1, n-1] 范围内
        if ($r->compare(BigInteger::one()) < 0 || $r->compare($curve->n) >= 0 ||
            $s->compare(BigInteger::one()) < 0 || $s->compare($curve->n) >= 0) {
            return false;
        }

        // 计算 Z 值
        $z = $curve->calculateZ($x, $y, $userId);

        // 计算消息摘要
        $digest = $this->sm3Hash(hex2bin($z . bin2hex($message)));
        $e = new BigInteger($digest, 16);

        // 计算 t = (r + s) mod n
        $t = $r->add($s)->mod($curve->n);

        // 检查 t 是否为 0
        if ($t->equals(BigInteger::zero())) {
            return false;
        }

        // 计算点 (x1, y1) = s * G + t * P，其中 P 是公钥点 (x, y)
        $point1 = $curve->multiplyG($s);
        $point2 = $curve->multiplyPoint($x, $y, $t);
        list($x1, $y1) = $curve->addPoints($point1[0], $point1[1], $point2[0], $point2[1]);

        // 计算 R = (e + x1) mod n
        return $e->add($x1)->mod($curve->n)->equals($r);
    }


//    public function verify($message, $userId, $base64Signature, $base64PublicKey)
//    {
//        // 解码 Base64 签名和公钥
//        $signatureBin = base64_decode($base64Signature);
//        $publicKeyBin = bin2hex(base64_decode($base64PublicKey));
//
////        var_dump($publicKeyBin[0], ord($publicKeyBin[0]) == 0x04);die();
//        // 提取 r 和 s 值 (各32字节)
//        $r = new BigInteger(bin2hex(substr($signatureBin, 0, 32)), 16);
//        $s = new BigInteger(bin2hex(substr($signatureBin, 32, 32)), 16);
//
//        // 提取公钥坐标 (x, y)
//        // 公钥通常为04 || x || y 格式，其中04表示未压缩格式
//        if (strlen($publicKeyBin) >= 65 && ord($publicKeyBin[0]) == 0x04) {
//            $x = new BigInteger(bin2hex(substr($publicKeyBin, 1, 32)), 16);
//            $y = new BigInteger(bin2hex(substr($publicKeyBin, 33, 32)), 16);
//        } else {
//            throw new \Exception("不支持的公钥格式");
//        }
//
//        // SM2 曲线参数
//        $curve = new SM2Curve();
//
//        // 验证 r 和 s 是否在 [1, n-1] 范围内
//        if ($r->compare(BigInteger::one()) < 0 || $r->compare($curve->n) >= 0 ||
//            $s->compare(BigInteger::one()) < 0 || $s->compare($curve->n) >= 0) {
//            return false;
//        }
//
//        // 计算 Z 值
//        $z = $curve->calculateZ($userId, $x, $y);
//
//        // 计算消息摘要
//        $digest = $this->sm3Hash($z . $message);
//        $e = new BigInteger(bin2hex($digest), 16);
//
//        // 计算 t = (r + s) mod n
//        $t = $r->add($s)->mod($curve->n);
//
//        // 检查 t 是否为 0
//        if ($t->equals(BigInteger::zero())) {
//            return false;
//        }
//
//        // 计算点 (x1, y1) = s * G + t * P，其中 P 是公钥点 (x, y)
//        $point1 = $curve->multiplyG($s);
//        $point2 = $curve->multiplyPoint($x, $y, $t);
//        list($x1, $y1) = $curve->addPoints($point1[0], $point1[1], $point2[0], $point2[1]);
//
//        // 计算 R = (e + x1) mod n
//        $R = $e->add($x1)->mod($curve->n);
//
//        // 验证 R 是否等于 r
//        return $R->equals($r);
//    }

    /**
     * 生成符合要求的随机数 k
     * @param BigInteger $n 曲线的阶
     * @return BigInteger 随机数 k
     * @throws \Exception
     */
    protected function generateRandomK(BigInteger $n): BigInteger
    {
        // 生成 1 <= k < n 的随机数
        if (function_exists('gmp_random_range')) {
            // 使用GMP扩展生成随机范围的大整数
            $k_value = gmp_random_range(gmp_init(1), gmp_sub($n->value, gmp_init(1)));
            $k = new BigInteger('0');
            $k->value = $k_value;
            return $k;
        } else {
            // 手动生成随机数
            $bytes = ceil(gmp_strval(gmp_div($n->value, gmp_init(256)), 10));
            $bstr = '';
            for ($i = 0; $i < $bytes; $i++) {
                $bstr .= chr(mt_rand(0, 255));
            }

            $k = new BigInteger(bin2hex($bstr), 16);

            // 确保 k 在正确范围内: 1 <= k < n
            $k = $k->mod($n);

            if ($k->equals(BigInteger::zero())) {
                return new BigInteger('1');
            }

            return $k;
        }
    }
}