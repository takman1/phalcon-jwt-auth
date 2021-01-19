<?php

namespace Dmkit\Phalcon\Auth\TokenGetter\Handler;

use Dmkit\Phalcon\Auth\TokenGetter\AdapterInterface;
use Phalcon\Session\Adapter as SessionAdapter;

/**
 * Dmkit\Phalcon\Auth\TokenGetter\Handle\Header.
 */
class Session implements AdapterInterface
{
	// session key
	private $key='jwt-token';

	private $session;

	public function __construct(SessionAdapter $session, ?string $key = null)
    {
        $this->session = $session;
        $this->key = $key ?? $this->key;
    }

    /**
     * Gets the token from the headers
     *
     * @return string
     */
	public function parse() : string
	{
	    if (!$this->session->has($this->key)) {
	        return '';
        }

	    return $this->session->get($this->key);
	}

	public function hasToken(): bool
    {
        return $this->session->has($this->key);
    }

	public function removeToken()
    {
        $this->session->remove($this->key);
    }
}
