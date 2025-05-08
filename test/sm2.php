<?php

require_once  __DIR__ . '/../vendor/autoload.php';

$prvKey = 'APvZtjhysKTpdjZ0WmnLYDl/heobjC41C9/CP7k+GGY3';
$platformPubKey = 'BNHKza0nKVmi6L4fKm0+/lXux32fo+4X1d630sIeJLmen1BHr/DMntMm29ICNdYkGPT/i4dOT8P6eaUV4MR55zs=';
$message = 'a';

$sign = \Gm\Helper\SM2::sign($message, $prvKey, '1234567812345678');

var_dump($sign);

$isV = \Gm\Helper\SM2::verify($message, $sign, $platformPubKey, '1234567812345678');
var_dump($isV);