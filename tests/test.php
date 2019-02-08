<?php
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload
//require_once __DIR__ .
use TREES\TreesTool;
use TREES\TreesStorageKey;

//create StorageKey
print("Test: generateNewKeypair \n");
$trees = new TreesTool();
$st = $trees->generateNewKeypair("12345678");
var_dump(get_object_vars($st));

//TODO: try to encrypt
//TODO: try to decrypt


//TODO: change Password
print("Test: changePassword \n");
$trees->changePassword("12345678", "87654321", $st);
var_dump(get_object_vars($st));

//TODO: try to encrypt
//TODO: try to decrypt
