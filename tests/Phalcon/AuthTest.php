<?php

use Dmkit\Phalcon\Auth\Auth;
use Dmkit\Phalcon\Auth\TokenGetter\Handler\Session;
use Dmkit\Phalcon\Auth\TokenGetter\TokenGetter;
use Dmkit\Phalcon\Auth\TokenGetter\Handler\Header;
use Dmkit\Phalcon\Auth\TokenGetter\Handler\QueryStr;
use Phalcon\Http\RequestInterface;
use Phalcon\Session\AdapterInterface;
use PHPUnit\Framework\TestCase;
use Firebase\JWT\JWT;

class AuthTest extends TestCase
{

	protected $parser;
	protected $jwt;

	protected $secretKey;
	protected $jwtSessionTokenName;

	protected $options;

	protected function setUp()
	{
		$this->secretKey = 'secret key';
		$this->jwtSessionTokenName = 'jwt-session-name';

		$this->options = [
				'sub' => 123,
				'exp' => 120
			];

		$options = $this->options;
		$options['exp'] = strtotime('+2 hours');

		$this->jwt = JWT::encode($options, $this->secretKey);
	}

	public function testMake()
	{
		$auth = new Auth;

		// pass exp as constructor
		$token = $auth->make($this->options, $this->secretKey);
		$this->assertEquals($this->jwt, $token);
	}

	public function testWithEmptyAuth()
	{
		$auth = new Auth;
		$auth->id();
		$this->assertEquals(NULL, $auth->id());
	}

	public function testQueryStringSuccess()
	{
		$response = $this->createMock(RequestInterface::class);
		$response->method('getQuery')->willReturn($this->jwt);

		$query = new QueryStr($response);

		$tokenGetter = new TokenGetter($query);

		$auth = new Auth;
		$auth->setAlgo('HS256');
        $auth->setLeeway(1);

		$this->assertTrue($auth->check($tokenGetter, $this->secretKey));

		$this->assertEquals(123, $auth->id());

		$payload = $this->options;
        $payload['exp'] = strtotime('+2 hours');

		$this->assertEquals($payload, $auth->data());
		$this->assertEquals($payload['sub'], $auth->data('sub'));
	}

	public function testHeaderSuccess()
	{
		$response = $this->createMock(RequestInterface::class);
		$response->method('getHeader')->willReturn('Bearer ' . $this->jwt);

		$header = new Header($response);
		$header->setPrefix('Bearer');

		$tokenGetter = new TokenGetter($header);

		$auth = new Auth;

		$this->assertTrue($auth->check($tokenGetter, $this->secretKey));

		$this->assertEquals(123, $auth->id());

		$payload = $this->options;
        $payload['exp'] = strtotime('+2 hours');

		$this->assertEquals($payload, $auth->data());
		$this->assertEquals($payload['sub'], $auth->data('sub'));
	}

	public function testSessionSuccess()
	{
		$session = $this->createMock(AdapterInterface::class);
		$session->method('has')->willReturn(true);
        $session->method('get')->willReturn($this->jwt);

		$session = new Session($session, $this->jwtSessionTokenName);

		$tokenGetter = new TokenGetter($session);

		$auth = new Auth;
		$auth->setAlgo('HS256');
        $auth->setLeeway(1);

		$this->assertTrue($auth->check($tokenGetter, $this->secretKey));

		$this->assertEquals(123, $auth->id());

		$payload = $this->options;
        $payload['exp'] = strtotime('+2 hours');

		$this->assertEquals($payload, $auth->data());
		$this->assertEquals($payload['sub'], $auth->data('sub'));
	}

	public function testSessionInvalidToken()
	{
		$session = $this->createMock(AdapterInterface::class);
		$session->method('has')->willReturn(true);
        $session->method('get')->willReturn($this->jwt . '1');

		$session = new Session($session, $this->jwtSessionTokenName);

		$tokenGetter = new TokenGetter($session);

		$auth = new Auth;

		$this->assertFalse($auth->check($tokenGetter, $this->secretKey));

		$this->assertNull($auth->id());
	}

	public function testEmptyToken()
	{
		$response = $this->createMock(RequestInterface::class);
		$session = $this->createMock(AdapterInterface::class);
		$response->method('getQuery')->willReturn('');
		$response->method('getHeader')->willReturn('');
        $session->method('has')->willReturn(false);
        $session->method('get')->willReturn(null);

		$query = new QueryStr($response);
		$header = new Header($response);
		$session = new Session($session, $this->jwtSessionTokenName);

		$tokenGetter = new TokenGetter($header, $query, $session);

		$auth = new Auth;

		$this->assertFalse($auth->check($tokenGetter, $this->secretKey));
		$this->assertCount(1, $auth->getMessages());
		$this->assertEquals('missing token', $auth->getMessages()[0]);
	}

	public function testCheckCallback()
	{
		$response = $this->createMock(RequestInterface::class);
		$response->method('getQuery')->willReturn($this->jwt);


		$auth = new Auth;

		$auth->onCheck(function($auth) {
			$auth->appendMessage('callback 1');
		});

		$auth->onCheck(function($auth) {
			$auth->appendMessage('callback 2');
			return false;
		});

		$auth->onCheck(function($auth) {
			$auth->appendMessage('callback 3');
		});

		$this->assertTrue( !$auth->check(new QueryStr($response), $this->secretKey) );

		// makse sure callback were properly called
		$expected_errors = [
			'callback 1', 'callback 2'
		];
		$this->assertEquals($expected_errors, $auth->getMessages());
	}


	public function testCheckFail()
	{
		// let's expired the jwt
		$response = $this->createMock(RequestInterface::class);
		$response->method('getQuery')->willReturn($this->jwt);
        $adapter = new QueryStr($response);
        $adapter->setKey('_token');

		$auth = new Auth;

		JWT::$timestamp = strtotime('+1 week');

		$this->assertTrue( !$auth->check(new TokenGetter($adapter), $this->secretKey) );

		$expected_errors = ['Expired token'];

		$this->assertEquals($expected_errors, $auth->getMessages());
	}

}
