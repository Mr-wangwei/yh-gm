<?php
/**
 * GmSSL PHP Extension
 * @link https://github.com/GmSSL/GmSSL-PHP
 * @version 1.1.0
 */


// Predefined Constants
const GMSSL_PHP_VERSION = "1.1.0";
const GMSSL_LIBRARY_VERSION = "GmSSL 3.1.1";
const GMSSL_SM3_DIGEST_SIZE = 32;
const GMSSL_SM3_HMAC_SIZE = 32;
const GMSSL_SM3_HMAC_MIN_KEY_SIZE = 16;
const GMSSL_SM4_KEY_SIZE = 16;
const GMSSL_SM4_BLOCK_SIZE = 16;
const GMSSL_SM4_CBC_IV_SIZE = 16;
const GMSSL_SM4_CTR_IV_SIZE = 16;
const GMSSL_SM4_GCM_MIN_IV_SIZE = 1;
const GMSSL_SM4_GCM_MAX_IV_SIZE = 64;
const GMSSL_SM4_GCM_DEFAULT_IV_SIZE = 12;
const GMSSL_SM4_GCM_MAX_TAG_SIZE = 16;
const GMSSL_SM2_DEFAULT_ID = "1234567812345678";
const GMSSL_SM2_MAX_PLAINTEXT_SIZE = 255;
const GMSSL_SM9_MAX_PLAINTEXT_SIZE = 255;
const GMSSL_ZUC_KEY_SIZE = 16;
const GMSSL_ZUC_IV_SIZE = 16;

/**
 * Generate cryptographic secure random bytes.
 *
 * @param int $length Number of bytes of the required random string. Must be a positive integer and should not be too long (such as over 1 MB).
 * @return string Return a string of generated random binary raw data.
 * @throws Exception Throws an Exception on failure.
 */
function gmssl_rand_bytes(int $length): string {}

/**
 * Calculate the SM3 digest of a message.
 *
 * @param string $message The input message.
 * @return string The SM3 digest of the message.
 */
function gmssl_sm3(string $message): string {}

/**
 * Calculate the SM3 HMAC of a message.
 *
 * @param string $key The HMAC key.
 * @param string $message The input message.
 * @return string The SM3 HMAC of the message.
 * @throws Error If the key length is less than GMSSL_SM3_HMAC_MIN_KEY_SIZE bytes.
 */
function gmssl_sm3_hmac(string $key, string $message): string {}

/**
 * Generate a key using SM3 PBKDF2.
 *
 * @param string $password The password.
 * @param string $salt The salt.
 * @param int $iter The number of iterations.
 * @param int $outlen The length of the output key.
 * @return string The generated key.
 * @throws Exception If there is a libgmssl inner error.
 */
function gmssl_sm3_pbkdf2(string $password, string $salt, int $iter, int $outlen): string {}

/**
 * Encrypt a single block of data using SM4 in ECB mode.
 *
 * @param string $key The SM4 key.
 * @param string $data_block The input plaintext block.
 * @return string The encrypted ciphertext block.
 * @throws Error If the key length is not GMSSL_SM4_KEY_SIZE bytes or the input block size is not GMSSL_SM4_BLOCK_SIZE bytes.
 */
function gmssl_sm4_encrypt(string $key, string $data_block): string {}

/**
 * Decrypt a single block of data using SM4 in ECB mode.
 *
 * @param string $key The SM4 key.
 * @param string $cipher_block The input ciphertext block.
 * @return string The decrypted plaintext block.
 * @throws Error If the key length is not GMSSL_SM4_KEY_SIZE bytes or the input block size is not GMSSL_SM4_BLOCK_SIZE bytes.
 */
function gmssl_sm4_decrypt(string $key, string $cipher_block): string {}

/**
 * Encrypt data using SM4 in CBC mode with padding.
 *
 * @param string $key The SM4 key.
 * @param string $iv The initialization vector.
 * @param string $data The input plaintext.
 * @return string The encrypted ciphertext.
 * @throws Error If the key length is not GMSSL_SM4_KEY_SIZE bytes or the IV length is not GMSSL_SM4_CBC_IV_SIZE bytes.
 * @throws Exception If there is a libgmssl inner error.
 */
function gmssl_sm4_cbc_encrypt(string $key, string $iv, string $data): string {}

/**
 * Decrypt data using SM4 in CBC mode with padding.
 *
 * @param string $key The SM4 key.
 * @param string $iv The initialization vector.
 * @param string $ciphertext The input ciphertext.
 * @return string The decrypted plaintext.
 * @throws Error If the key length is not GMSSL_SM4_KEY_SIZE bytes or the IV length is not GMSSL_SM4_CBC_IV_SIZE bytes.
 * @throws Exception If the decryption fails.
 */
function gmssl_sm4_cbc_decrypt(string $key, string $iv, string $ciphertext): string {}

/**
 * Encrypt data using SM4 in CTR mode.
 *
 * @param string $key The SM4 key.
 * @param string $iv The initialization vector.
 * @param string $data The input plaintext.
 * @return string The encrypted ciphertext.
 * @throws Error If the key length is not GMSSL_SM4_KEY_SIZE bytes or the IV length is not GMSSL_SM4_CTR_IV_SIZE bytes.
 */
function gmssl_sm4_ctr_encrypt(string $key, string $iv, string $data): string {}

/**
 * Encrypt data using SM4 in GCM mode.
 *
 * @param string $key The SM4 key.
 * @param string $iv The initialization vector.
 * @param string $aad The associated authenticated data.
 * @param int $taglen The length of the authentication tag.
 * @param string $data The input plaintext.
 * @return string The encrypted ciphertext.
 */
#[Pure]
function gmssl_sm4_gcm_encrypt(string $key, string $iv, string $aad, int $taglen, string $data): string {} {}

/**
 * Decrypt data using SM4 in GCM mode.
 *
 * @param string $key The SM4 key.
 * @param string $iv The initialization vector.
 * @param string $aad The associated authenticated data.
 * @param int $taglen The length of the authentication tag.
 * @param string $ciphertext The input ciphertext.
 * @return string The decrypted plaintext.
 */
function gmssl_sm4_gcm_decrypt(string $key, string $iv, string $aad, int $taglen, string $ciphertext): string {}

/**
 * Generate an SM2 key pair.
 *
 * @return string The generated SM2 key pair.
 */
function gmssl_sm2_key_generate(): string {}

/**
 * Export SM2 private key to an encrypted PEM file.
 *
 * @param string $keypair The SM2 key pair.
 * @param string $file The output PEM file path.
 * @param string $passphrase The passphrase to encrypt the PEM file.
 * @return bool true on success or false on failure.
 */
function gmssl_sm2_private_key_info_encrypt_to_pem(string $keypair, string $file, string $passphrase): bool {}

/**
 * Export SM2 public key to a PEM file.
 *
 * @param string $public_key The SM2 public key.
 * @param string $file The output PEM file path.
 * @return bool true on success or false on failure.
 */
function gmssl_sm2_public_key_info_to_pem(string $public_key, string $file): bool {}

/**
 * Import SM2 private key from an encrypted PEM file.
 *
 * @param string $file The input encrypted PEM file path.
 * @param string $passphrase The passphrase to decrypt the PEM file.
 * @return string The imported SM2 private key.
 */
function gmssl_sm2_private_key_info_decrypt_from_pem(string $file, string $passphrase): string {}

/**
 * Import SM2 public key from a PEM file.
 *
 * @param string $file The public key PEM file.
 * @return string SM2 public key, a 96-byte string with the last 32-byte private key all zeros.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm2_public_key_info_from_pem(string $file): string {}

/**
 * Sign a message using SM2.
 *
 * @param string $keypair Signer's SM2 private key, typically from `gmssl_sm2_key_generate`.
 * @param string $id Signer's identity string. If no explicit identity scheme is specified, the default value GMSSL_SM2_DEFAULT_ID should be used.
 * @param string $message To be signed message of any length.
 * @return string The generated SM2 signature in DER encoding, the raw data bytes start with a `0x30` and the typical signature length is 70, 71 or 72 bytes.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm2_sign(string $keypair, string $id, string $message): string {}

/**
 * Verify an SM2 signature.
 *
 * @param string $public_key Signer's SM2 public key, typically from `gmssl_sm2_public_key_info_from_pem` or `gmssl_cert_get_subject_public_key`.
 * @param string $id Signer's identity string. If no explicit identity scheme is specified, the default value GMSSL_SM2_DEFAULT_ID should be used.
 * @param string $message The signed message.
 * @param string $signature The SM2 signature in DER-encoding.
 * @return bool true or false.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm2_verify(string $public_key, string $id, string $message, string $signature): bool {}

/**
 * Encrypt a short secret message using SM2 public key.
 *
 * @param string $public_key The SM2 public key.
 * @param string $data The plaintext to encrypt.
 * @return string The encrypted ciphertext.
 */
function gmssl_sm2_encrypt(string $public_key, string $data): string {}

/**
 * Decrypt an SM2 ciphertext using SM2 private key.
 *
 * @param string $keypair The SM2 private key.
 * @param string $ciphertext The ciphertext to decrypt.
 * @return string The decrypted plaintext.
 */
function gmssl_sm2_decrypt(string $keypair, string $ciphertext): string {}

/**
 * Generate an SM9 signing master key.
 *
 * @return string SM9 signing master key.
 * @throws Exception Throw exceptions on GmSSL library inner errors.
 */
function gmssl_sm9_sign_master_key_generate(): string {}

/**
 * Extract the signing private key from SM9 master key with signer's ID.
 *
 * @param string $master_key The SM9 signing master key.
 * @param string $id The signer's ID.
 * @return string The extracted SM9 signing private key.
 */
function gmssl_sm9_sign_master_key_extract_key(string $master_key, string $id): string {}

/**
 * Export SM9 signing master key to an encrypted PEM file.
 *
 * @param string $master_key The SM9 signing master key.
 * @param string $file The output PEM file path.
 * @param string $passphrase The passphrase to encrypt the PEM file.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_sign_master_key_info_encrypt_to_pem(string $master_key, string $file, string $passphrase): bool {}

/**
 * Import SM9 signing master key from an encrypted PEM file.
 *
 * @param string $file The input password encrypted SM9 signing master key PEM file path.
 * @param string $passphrase The passphrase to decrypt the PEM file.
 * @return string SM9 signing master key
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm9_sign_master_key_info_decrypt_from_pem(string $file, string $passphrase): string {}

/**
 * Export SM9 signing master public key to a file.
 *
 * @param string $master_key The SM9 signing master key.
 * @param string $file The output file path.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_sign_master_public_key_to_pem(string $master_key, string $file): bool {}

/**
 * Import SM9 signing master public key from a file.
 *
 * @param string $file The SM9 signing master public key PEM file.
 * @return string SM9 signing master public key.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm9_sign_master_public_key_from_pem(string $file): string {}

/**
 * Export user's SM9 signing key to an encrypted PEM file.
 *
 * @param string $sign_key The user's SM9 signing key.
 * @param string $file The output PEM file path.
 * @param string $passphrase The passphrase to encrypt the PEM file.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_sign_key_info_encrypt_to_pem(string $sign_key, string $file, string $passphrase): bool {}

/**
 * Import user's SM9 signing key from an encrypted PEM file.
 *
 * @param string $file The input password encrypted user's SM9 signing key PEM file path.
 * @param string $passphrase The passphrase to decrypt the PEM file.
 * @return string The user's SM9 signing key.
 */
function gmssl_sm9_sign_key_info_decrypt_from_pem(string $file, string $passphrase): string {}

/**
 * Sign a message with user's SM9 signing key.
 *
 * @param string $sign_key Signer's SM9 private key.
 * @param string $message To be signed message of any length.
 * @return string The generated SM9 signature in DER encoding, the raw data bytes start with a `0x30` byte.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm9_sign(string $sign_key, string $message): string {}

/**
 * Verify an SM9 signature of a message with signer's ID.
 *
 * @param string $master_public_key SM9 signing master public key.
 * @param string $id Signer's identity string.
 * @param string $message Signed message of any length.
 * @param string $signature SM9 signature.
 * @return bool true or false.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm9_verify(string $master_public_key, string $id, string $message, string $signature): bool {}

/**
 * Generate an SM9 encryption master key.
 *
 * @return string SM9 encryption master key.
 * @throws Exception Throw exceptions on GmSSL library inner errors.
 */
function gmssl_sm9_enc_master_key_generate(): string {}

/**
 * Extract the encryption key from SM9 encryption master key with user's ID.
 *
 * @param string $master_key The SM9 encryption master key.
 * @param string $id The user's ID.
 * @return string The extracted SM9 encryption key.
 */
function gmssl_sm9_enc_master_key_extract_key(string $master_key, string $id): string {}

/**
 * Export SM9 encryption master key to an encrypted PEM file.
 *
 * @param string $master_key The SM9 encryption master key.
 * @param string $file The output PEM file path.
 * @param string $passphrase The passphrase to encrypt the PEM file.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_enc_master_key_info_encrypt_to_pem(string $master_key, string $file, string $passphrase): bool {}

/**
 * Import SM9 encryption master key from an encrypted PEM file.
 *
 * @param string $file The input encrypted SM9 encryption master key PEM file path.
 * @param string $passphrase The passphrase to decrypt the PEM file.
 * @return string The imported SM9 encryption master key.
 */
function gmssl_sm9_enc_master_key_info_decrypt_from_pem(string $file, string $passphrase): string {}

/**
 * Export SM9 encryption master public key to a file.
 *
 * @param string $master_key The SM9 encryption master key.
 * @param string $file The output file path.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_enc_master_public_key_to_pem(string $master_key, string $file): bool {}

/**
 * Import SM9 encryption master public key from a file.
 *
 * @param string $file The SM9 encryption master public key PEM file.
 * @return string SM9 encryption master public key.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_sm9_enc_master_public_key_from_pem(string $file): string {}

/**
 * Export user's SM9 encryption key to an encrypted PEM file.
 *
 * @param string $enc_key The user's SM9 encryption key.
 * @param string $file The output PEM file path.
 * @param string $passphrase The passphrase to encrypt the PEM file.
 * @return bool true on success or false on failure.
 */
function gmssl_sm9_enc_key_info_encrypt_to_pem(string $enc_key, string $file, string $passphrase): bool {}

/**
 * Import user's SM9 encryption key from an encrypted PEM file.
 *
 * @param string $file The input encrypted user's SM9 encryption key PEM file path.
 * @param string $passphrase The passphrase to decrypt the PEM file.
 * @return string The user's SM9 encryption key.
 */
function gmssl_sm9_enc_key_info_decrypt_from_pem(string $file, string $passphrase): string {}

/**
 * Encrypt a message using SM9 encryption.
 *
 * @param string $master_public_key The SM9 encryption master public key.
 * @param string $id The user's ID.
 * @param string $data The plaintext to encrypt.
 * @return string The encrypted ciphertext.
 */
function gmssl_sm9_encrypt(string $master_public_key, string $id, string $data): string {}

/**
 * Decrypt an SM9 ciphertext using the user's SM9 encryption key.
 *
 * @param string $enc_key The user's SM9 encryption key.
 * @param string $id The user's ID.
 * @param string $ciphertext The ciphertext to decrypt.
 * @return string The decrypted plaintext.
 */
function gmssl_sm9_decrypt(string $enc_key, string $id, string $ciphertext): string {}

/**
 * Import a X.509 certificate from a PEM file.
 *
 * @param string $path Certificate file path, the certificate should be a SM2 certficate in PEM format.
 * @return string SM2 certificate. The raw data of the return value is the DER-encoding bytes of the certificate.
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_cert_from_pem(string $path): string {}

/**
 * Print details of a X.509 certificate.
 *
 * @param string $cert SM2 certificate, typically from `gmssl_cert_from_pem`.
 * @param string $label Label string that will be printed at the first line of the output.
 * @return bool true or false
 * @throws Exception Throw exceptions on invalid parameters and GmSSL library inner errors.
 */
function gmssl_cert_print(string $cert, string $label): bool {}

/**
 * Get the serial number of a X.509 certificate.
 *
 * @param string $cert The X.509 certificate.
 * @return string The serial number of the certificate.
 */
function gmssl_cert_get_serial_number(string $cert): string {}

/**
 * Get the issuer information of a X.509 certificate.
 *
 * @param string $cert The X.509 certificate.
 * @return array The issuer information of the certificate.
 */
function gmssl_cert_get_issuer(string $cert): array {}

/**
 * Get the subject information of a X.509 certificate.
 *
 * @param string $cert The X.509 certificate.
 * @return array The subject information of the certificate.
 */
function gmssl_cert_get_subject(string $cert): array {}

/**
 * Get the validity information of a X.509 certificate.
 *
 * @param string $cert The X.509 certificate.
 * @return array The validity information of the certificate.
 */
function gmssl_cert_get_validity(string $cert): array {}

/**
 * Get the subject public key of a X.509 certificate.
 *
 * @param string $cert The X.509 certificate.
 * @return string The subject public key of the certificate.
 */
function gmssl_cert_get_subject_public_key(string $cert): string {}

/**
 * Verify a X.509 certificate using a CA certificate.
 *
 * @param string $cert The certificate to verify.
 * @param string $cacert The CA certificate.
 * @param string $sm2_id The identity string. If not specified, GMSSL_SM2_DEFAULT_ID should be used.
 * @return bool The verification result.
 */
function gmssl_cert_verify_by_ca_cert(string $cert, string $cacert, string $sm2_id): bool {}
