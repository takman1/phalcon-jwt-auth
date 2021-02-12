<?php

namespace Dmkit\Phalcon\Auth;

use Dmkit\Phalcon\Auth\TokenGetter\AdapterInterface as TokenGetter;

/**
 * Dmkit\Phalcon\Auth\Auth.
 */
class Auth extends Adapter
{
	// callbacks on check
	protected $_onCheckCb = [];

	/**
     * Encodes array into JWT.
     *
     * @param array $payload
     * @param string $key
     *
     * @return string
     */
	public function make(array $payload, string $key): string
	{
		return $this->encode($payload, $key);
	}

	/**
     * Adds callback on check method.
     *
     * @param callable $callback
     *
     */
	public function onCheck(callable $callback)
	{
		$this->_onCheckCb[] = $callback;
	}

	/**
     * Checks and validates JWT. 
     * Calls the oncheck callbacks and pass self as parameter.
     *
     * @param TokenGetter $parser
     * @param string $key
     *
     * @return bool
     */
	public function check(TokenGetter $parser, string $key): bool
	{
		$token = $parser->parse();
		if (!$token) {
			$this->appendMessage('missing token');
		}

		$payload = $token
            ? $this->decode($token, $key)
            : null;
		if (empty($payload)) {
            $parser->clearSessionToken();

			return false;
		}
		$this->payload = $payload;

		// if any of the callback return false, this will immediately return false
		foreach ($this->_onCheckCb as $callback) {
			if (false === $callback($this)) {
				return false;
			}
		}

		return true;
	}
}
