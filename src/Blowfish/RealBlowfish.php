<?php
namespace Blowfish;

class RealBlowfish {
  const CIPHER = MCRYPT_BLOWFISH;
  const MODE = MCRYPT_MODE_ECB;

  /* Cryptographic key of length 16, 24 or 32. NOT a password! */
  private $key;
  public function __construct($key) {
    $this->key = $key;
  }
  public function encrypt($plaintext) {
    //$ivSize = mcrypt_get_iv_size ( self::CIPHER, self::MODE );
    //$iv = mcrypt_create_iv ( $ivSize, MCRYPT_DEV_RANDOM );
    // Fester Initialisation Vector um immer gleiche Ergebnisse zu bekommen.
    $iv =  '12345678';
    $ciphertext = mcrypt_encrypt ( self::CIPHER, $this->key, $plaintext, self::MODE, $iv );
    return base64_encode ( $ciphertext );
    //return base64_encode ( $iv . $ciphertext );
  }

  public function decrypt($ciphertext) {
    $ciphertext = base64_decode ( $ciphertext );
    $ivSize = mcrypt_get_iv_size ( self::CIPHER, self::MODE );
    // Keine länge des IV feststellen, da wir keinen mit in das Ergebnis coden
    $ivSize=0;
    if (strlen ( $ciphertext ) < $ivSize) {
      throw new \Exception ( 'Missing initialization vector' );
    }

    $iv = substr ( $ciphertext, 0, $ivSize );
    $ciphertext = substr ( $ciphertext, $ivSize );
    $plaintext = mcrypt_decrypt ( self::CIPHER, $this->key, $ciphertext, self::MODE, $iv );
    return rtrim ( $plaintext, "\0" );
  }
}