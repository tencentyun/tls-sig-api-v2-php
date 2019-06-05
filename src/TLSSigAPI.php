<?php

namespace Tencent;

if (version_compare(PHP_VERSION, '5.1.2') < 0) {
    trigger_error('need php 5.1.2 or newer', E_USER_ERROR);
}

class TLSSigAPI {

    private $key = false;
    private $sdkappid = 0;

    public function __construct($sdkappid, $key) {
        $this->sdkappid = $sdkappid;
        $this->key = $key;
    }

    /**
     * 用于 url 的 base64 encode
     * '+' => '*', '/' => '-', '=' => '_'
     * @param string $string 需要编码的数据
     * @return string 编码后的base64串，失败返回false
     * @throws \Exception
     */
    private function base64_url_encode($string) {
        static $replace = Array('+' => '*', '/' => '-', '=' => '_');
        $base64 = base64_encode($string);
        if ($base64 === false) {
            throw new \Exception('base64_encode error');
        }
        return str_replace(array_keys($replace), array_values($replace), $base64);
    }

    /**
     * 用于 url 的 base64 decode
     * '+' => '*', '/' => '-', '=' => '_'
     * @param string $base64 需要解码的base64串
     * @return string 解码后的数据，失败返回false
     * @throws \Exception
     */
    private function base64_url_decode($base64) {
        static $replace = Array('+' => '*', '/' => '-', '=' => '_');
        $string = str_replace(array_values($replace), array_keys($replace), $base64);
        $result = base64_decode($string);
        if ($result == false) {
            throw new \Exception('base64_url_decode error');
        }
        return $result;
    }

    /**
     * 使用 hmac sha256 生成 sig 字段内容，经过 base64 编码
     * @param $identifier 用户名，utf-8 编码
     * @param $curr_time 当前生成 sig 的 unix 时间戳
     * @param $expire 有效期，单位秒
     * @return string base64 后的 sig
     */
    private function hmacsha256($identifier, $curr_time, $expire) {
        $content_to_be_signed = "TLS.identifier:" . $identifier . "\n"
            . "TLS.sdkappid:" . $this->sdkappid . "\n"
            . "TLS.time:" . $curr_time . "\n"
            . "TLS.expire:" . $expire . "\n";
        return base64_encode(hash_hmac( 'sha256', $content_to_be_signed, $this->key, true));
    }

    /**
     * 生成签名
     * @param $identifier 用户账号
     * @param int $expire 过期时间，单位秒，默认 180 天
     * @return string 签名字符串
     * @throws \Exception
     */
    public function genSig($identifier, $expire = 15552000) {
        $curr_time = time();
        $sig_array = Array(
            'TLS.ver' => '2.0',
            'TLS.identifier' => strval($identifier),
            'TLS.sdkappid' => intval($this->sdkappid),
            'TLS.expire' => intval($expire),
            'TLS.time' => intval($curr_time)
        );

        $sig_array['TLS.sig'] = $this->hmacsha256($identifier, $curr_time, $expire);
        if ($sig_array['TLS.sig'] === false) {
            throw new \Exception('base64_encode error');
        }
        $json_str_sig = json_encode($sig_array);
        if ($json_str_sig === false) {
            throw new \Exception('json_encode error');
        }
        $compressed = gzcompress($json_str_sig);
        if ($compressed === false) {
            throw new \Exception('gzcompress error');
        }
        return $this->base64_url_encode($compressed);
    }

    /**
     * 验证签名
     * @param string $sig 签名内容
     * @param string $identifier 需要验证用户名，utf-8 编码
     * @param int $init_time 生成时间
     * @param int $expire_time 有效期 3600 秒
     * @param string $error_msg 失败时的错误信息
     * @return boolean 验证是否成功
     * @throws \Exception
     */
    public function verifySig($sig, $identifier, &$init_time, &$expire_time, &$error_msg) {
        try {
            $error_msg = '';
            $compressed_sig = $this->base64_url_decode($sig);
            $uncompressed_sig = gzuncompress($compressed_sig);
            if ($uncompressed_sig === false) {
                throw new \Exception('gzuncompress error');
            }
            $sig_array = json_decode($uncompressed_sig);
            if ($sig_array == false) {
                throw new \Exception('json_decode error');
            }
            $sig_array = (array)$sig_array;
            if ($sig_array['TLS.identifier'] !== $identifier) {
                throw new \Exception("identifier dosen't match");
            }
            if ($sig_array['TLS.sdkappid'] != $this->sdkappid) {
                throw new \Exception("sdkappid dosen't match");
            }
            $sig = $sig_array['TLS.sig'];
            if ($sig == false) {
                throw new \Exception('sig field is missing');
            }

            $init_time = $sig_array['TLS.time'];
            $expire_time = $sig_array['TLS.expire'];

            $curr_time = time();
            if ($curr_time > $init_time+$expire_time) {
                throw new \Exception('sig expired');
            }

            $sigCalculated = $this->hmacsha256($identifier, $init_time, $expire_time);

            if ($sig != $sigCalculated) {
                throw new \Exception('verify failed');
            }

            return true;
        } catch (\Exception $ex) {
            $error_msg = $ex->getMessage();
            return false;
        }
    }
}
