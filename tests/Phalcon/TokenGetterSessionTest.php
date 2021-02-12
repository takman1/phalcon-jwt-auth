<?php

use Dmkit\Phalcon\Auth\TokenGetter\Handler\Session;
use Phalcon\Session\AdapterInterface;
use PHPUnit\Framework\TestCase;

class TokenGetterSessionTest extends TestCase
{
	public function testParser()
	{
		$token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
		
		$response = $this->createMock(AdapterInterface::class);
		$response->method('has')->willReturn(true);
		$response->method('get')->willReturn($token);

		$query = new Session($response);
		$this->assertEquals($token, $query->parse());
	}
}