<?php

namespace Dmkit\Phalcon\TokenGetter\Handler;

use Phalcon\Http\RequestInterface;
use Dmkit\Phalcon\TokenGetter\AdapterInterface;

abstract class Adapter implements AdapterInterface
{

	protected $_Request;

	public function __construct(RequestInterface $request)
	{
		$this->_Request = $request;
	}

	abstract public function parse(): string;
}