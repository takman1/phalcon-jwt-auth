<?php

namespace Dmkit\Phalcon\Auth\TokenGetter\Handler;

use Phalcon\Session\AdapterInterface as SessionAdapterInterface;

/**
 * Dmkit\Phalcon\Auth\TokenGetter\Handle\Header.
 */
class Session extends Adapter
{
	// session key
	protected $key = 'jwt-token';

	private $session;

	public function __construct(SessionAdapterInterface $session, ?string $key = null)
    {
        $this->session = $session;
        $this->key = $key ?? $this->key;
    }

    /**
     * Gets the token from the headers
     *
     * @return string
     */
	public function parse(): string
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
