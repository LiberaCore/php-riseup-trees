<?php
namespace TREES;

class TreesStorageKey
{
    public $OPS_LIMIT         = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    public $MEM_LIMIT         = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

    //private attributes
    public $publicKey         = "";
    public $lockedSecretBox   = "";
    public $skNonce           = "";
    public $salt              = "";
    public $pwhashAlgo        = 1;

}
