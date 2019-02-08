<?php
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload
//require_once __DIR__ .
use TREES\TreesTool;
use TREES\TreesStorageKey;

$trees = new TreesTool();
$st = $trees->generateNewKeypair("12345678");
var_dump(get_object_vars($st));
