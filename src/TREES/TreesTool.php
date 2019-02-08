<?php
namespace TREES;

class TreesTool
{
    public $OPS_LIMIT         = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    public $MEM_LIMIT         = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    public $SALT_BYTES        = 16;
    # ref: https://github.com/bitbeans/libsodium-net-doc/blob/master/secret-key_cryptography/authenticated_encryption.md
    # ref: https://github.com/crypto-rb/rbnacl/commit/d2b057a35e77b405ef5a36f126ca376de731065e
    public $NONCE_BYTES       = 24;
    # ref: https://github.com/bitbeans/libsodium-net-doc/blob/master/secret-key_cryptography/authenticated_encryption.md
    public $DIGEST_BYTES      = 32; //key bytes length for secret box crypto

    //private attributes
    public $publicKey         = NULL;
    public $lockedSecretBox   = NULL;
    public $skNonce           = NULL;


    function __construct() {
        //print "Im BaseClass Konstruktor\n";
    }

    public function generateNewKeypair($password)
    {
        $key = $this->newKey();
        return $this->encryptKey($key, $password);
    }


    public function changePassword($oldPassword, $newPassword)
    {
      $key = $this->decryptKey($oldPassword);
      return $this->encryptKey($key, $newPassword);
    }

    # ref: https://paragonie.com/book/pecl-libsodium/read/04-secretkey-crypto.md
    # //TODO: is sodium_crypto_secretbox able to encrypt bytes, or only string
    private function encryptKey($key, $password=NULL, $salt=NULL, $skNonce=NULL)
    {
      $symmetricKey = $this->passwordKDF($password, $salt);

      //check if nonce is set
      if(is_null($skNonce))
      {
        $skNonce = sodium_bin2hex(random_bytes($this->NONCE_BYTES));
      }

      //encrypt the secret key of the keypair
      $encryptedKey = sodium_crypto_secretbox(sodium_crypto_box_secretkey($key), sodium_hex2bin($skNonce), $symmetricKey);

      //save the key
      $this->publicKey = sodium_bin2hex(sodium_crypto_box_publickey($key));
      $this->lockedSecretbox = sodium_bin2hex($encryptedKey);
      print("EncryptedKey: " . $encryptedKey . "\n");
      print("PublicKey: " . $this->publicKey . "\n");
      print("LockedSecretBox: " . sodium_bin2hex($encryptedKey) . "\n");
    }

    private function decryptKey($password)
    {
      $passwordBytes = passwordKDF($password);
      $secretKey = sodium_crypto_secretbox_open($this->lockedSecretBox, $this->skNonce, $passwordBytes);
      if ($secretKey === false) {
          throw new Exception("Bad ciphertext");
      }


      $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
          $secretKey,
          $this->publickey
      );
      return $keypair;
    }

    #
    # generates a new Curve25519 private key
    #
    # reference: https://paragonie.com/book/pecl-libsodium/read/05-publickey-crypto.md
    private function newKey()
    {
      $kp = sodium_crypto_box_keypair();
      //$pk = sodium_crypto_box_secretkey($kp);
      return $kp;
    }

    # ref: https://paragonie.com/book/pecl-libsodium/read/07-password-hashing.md
    # $salt: as hex string
    private function passwordKDF($secret, $salt = NULL)
    {
      //check if salt is set as function argument
      if (is_null($salt))
      {
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
      }
      else {
        $salt = sodium_hex2bin($salt);
      }

      $seed = sodium_crypto_pwhash(
          $this->DIGEST_BYTES,
          $secret, //secret/password
          $salt, //salt
          $this->OPS_LIMIT,
          $this->MEM_LIMIT
      );
      return $seed;
    }
}
