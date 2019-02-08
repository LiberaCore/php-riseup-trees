<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files 
use PHPUnit\Framework\TestCase;
use TREES\TreesTool;

final class TreesToolTest extends TestCase
{
    public function testGenerateKey(): void
    {
        $trees = new TreesTool();
        $trees->generateNewKeypair("12345678");

        /*
        $this->assertInstanceOf(
            Email::class,
            Email::fromString('user@example.com')
        );
        */
    }

    public function testChangePassword(): void
    {
      /*
        $this->expectException(InvalidArgumentException::class);

        Email::fromString('invalid');
      */
    }
}
