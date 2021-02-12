<?php

namespace Dmkit\Phalcon\Auth;

use Exception;
use Firebase\JWT\JWT;

use function time;

/**
 * Dmkit\Phalcon\Auth\Adapter.
 */
abstract class Adapter implements AdapterInterface
{
	// payload for JWT
	protected $payload = [];

	// window time for jwt to expire
	protected $leeway;

	// supported algs are on JWT::$supported_algs
	protected $algo = 'HS256';

	protected $errorMsgs = [];

    /**
     * Converts mins to seconds.
     *
     * @param int $mins
     *
     * @return int
     */
	public function minToSec(int $mins)
	{
		return (60 * $mins);
	}

	/**
     * Sets leeway after JWT has expired.
     *
     * @param int $mins
     *
     */
	public function setLeeway(int $mins)
	{
		$this->leeway = $this->minToSec($mins);
	}

    /**
     * Sets algorith for hashing JWT.
     * See available Algos on JWT::$supported_algs
     *
     * @param string $alg
     */
	public function setAlgo(string $alg) {
		$this->algo = $alg;
	}

	/**
     * Decodes JWT.
     *
     * @param string $token
     * @param string $key
     *
     * @return array
     */
	protected function decode(string $token, string $key): array
	{
		try {
			if ($this->leeway) {
				JWT::$leeway = $this->leeway;
			}

			return (array) JWT::decode($token, $key, [$this->algo]);

		} catch(Exception $e) {
			$this->appendMessage($e->getMessage());

			return [];
		}
	}

	/**
     * Encodes array into JWT.
     *
     * @param array $payload
     * @param string $key
     *
     * @return string
     */
	protected function encode(array $payload, string $key)
	{
		if (isset($payload['exp'])) {
			$payload['exp'] = time() + $this->minToSec($payload['exp']);
		}

		return JWT::encode($payload, $key, $this->algo);
	}

	/**
     * Adds string to error messages.
     *
     * @param string $msg
     *
     */
	public function appendMessage(string $msg)
	{
		$this->errorMsgs[] = $msg;
	}

	/**
     * Returns error messages
     *
     * @return array
     */
	public function getMessages()
	{
		return $this->errorMsgs;
	}

	/**
     * Returns JWT payload sub or payload id.
     *
     * @return string
     */
	public function id()
	{
		return $this->payload['sub'] ?? $this->payload['id'] ?? NULL;
	}

    /**
     * Returns payload or value of payload key.
     *
     * @param string $field
     * @return array|string|null
     */
	public function data(string $field = '')
	{
		return !$field
            ? $this->payload
            : ($this->payload[$field] ?? null);
	}
}
