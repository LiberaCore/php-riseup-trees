<?php
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload
//require_once __DIR__ .
use TREES\TreesTool;

$trees = new TreesTool();
$trees->generateNewKeypair("12345678");
