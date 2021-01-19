<?php
namespace Dmkit\Phalcon\Auth\Middleware;

use Dmkit\Phalcon\Auth\TokenGetter\Handler\Session as SessionHandler;
use InvalidArgumentException;
use JsonException;
use Phalcon\Config;
use Phalcon\Session\Adapter as Session;
use Phalcon\Http\Request;
use Phalcon\Http\Response;
use Dmkit\Phalcon\Auth\Auth;
use Dmkit\Phalcon\Auth\TokenGetter\TokenGetter;
use Dmkit\Phalcon\Auth\TokenGetter\Handler\Header;
use Dmkit\Phalcon\Auth\TokenGetter\Handler\QueryStr;

use function array_merge;
use function call_user_func;
use function explode;
use function in_array;
use function json_encode;
use function preg_match;
use function str_replace;
use function strpos;

/**
 * Dmkit\Phalcon\Auth\Middleware\JwtAuthenticator.
 * The concept of controllers doesn't exist in Phalcon apps
 * so checking of URLS and methods have to be done on the Request level.
 */
class JwtAuthenticator
{
	// config section key
	public static $configSection = 'jwtAuth';

	// config section key
	public $jwtSessionTokenName;

	// JWT payload
	private $payload;

	// ignored urls
	private $ignoreUri;

	// JWT secret key
	private $secretKey;

	// Ignore OPTIONS for CORS support
	private $ignoreOptionsMethod = false;

	// Auth Object
	private $auth;

	// Unauthorized callback
    private $_onUnauthorized;

    /**
     * @var Request
     */
	private $request;

    /**
     * @var Response
     */
	private $response;

    /**
     * @var Session
     */
	private $session;

    /**
     * Sets app and config.
     *
     * @param Request $request
     * @param Response $response
     * @param Session $session
     * @param Config $config
     * @param string $configSection
     */
	public function __construct(Request $request, Response $response, Session $session, Config $config, string $configSection = '')
	{
		/**
		 * example of config:
		 * [jwtAuth]
		 * secretKey = nSrL7k4/7NcW|AN
		 * payload[exp] = 120
		 * payload[iss] = phalcon-jwt-auth 
		 * payload[sub] = 123 
		 * payload[name] = John Doe 
		 * payload[role] = admin 
		 * ignoreUri[] = regex:/register/:POST
		 * ignoreUri[] = /register
		 */

		self::$configSection = $configSection ?: self::$configSection;
		if(!$config->get(self::$configSection)) {
			throw new InvalidArgumentException('missing DI config jwtAuth and config param');
		}

		$jwtConfig = $config->get(self::$configSection)->toArray();

        // secret key is required
        if(!isset($jwtConfig['secretKey'])) {
            throw new InvalidArgumentException('missing jwt secret key');
        }

		if(!empty($jwtConfig['ignoreUri'])) {
			$this->ignoreUri = $jwtConfig['ignoreUri'];
		}

		$this->secretKey = $jwtConfig['secretKey'];
		$this->jwtSessionTokenName = $jwtConfig['session-token-name'] ?? null;
		$this->payload = (array) ($jwtConfig['payload'] ?? []);

		$this->auth = new Auth();
		$this->request = $request;
		$this->response = $response;
		$this->session = $session;
	}


	/**
     *  Ignore OPTIONS for CORS support
     *
     */
	public function setIgnoreOptionsMethod()
	{
		$this->ignoreOptionsMethod = true;
	}

	/**
     *  Checks if OPTIONS METHOD Should be ignored
     *
     */
	public function isIgnoreOptionsMethod()
	{
		return $this->ignoreOptionsMethod;
	}

    /**
     * Sets event authentication.
     * @return bool
     * @throws JsonException
     */
    public function beforeExecuteRoute()
    {
        // check if it has CORS support
        if ($this->isIgnoreOptionsMethod() &&  'OPTIONS' === $this->request->getMethod()) {
            return true;
        }

        if ($this->isIgnoreUri()) {
            /**
             * Let's try to parse if there's a token
             * but we don't want to get an invalid token
             */
            if (!$this->check() && 'missing token' !== ($this->getMessages()[0] ?? '')) {
                return $this->unauthorized();
            }

            return true;
        }

        if ($this->check()) {
            return true;
        }

        return $this->unauthorized();
    }

	/**
     * Checks the uri and method if it has a match in the passed self::$ignoreUris.
     *
     * @param string $requestUri
     * @param string $requestMethod HTTP METHODS
     *
     * @return bool
     */
	protected function hasMatchIgnoreUri(string $requestUri, string $requestMethod)
	{
		foreach ($this->ignoreUri as $uri) {
			if (false === strpos($uri, 'regex:')) {
				$type = 'str';
			} else {
				$type = 'regex';
				$uri = str_replace('regex:', '', $uri);
			}

			[$pattern, $methods] = (strpos($uri, ':') === false
                ? [$uri, false]
                : explode(':', $uri )
            );
			$methods = ( !$methods || empty($methods) ? false : explode(',', $methods) );

			$match = ('str' === $type
                ? ($requestUri === $pattern)
                : preg_match("#{$pattern}#", $requestUri)
            );
			if ($match && (!$methods || in_array($requestMethod, $methods))) {
				return true;
			}
		}

		return false;
	}

	/**
     * Checks if the URI and HTTP METHOD can bypass the authentication.
     *
     * @return bool
     */
	public function isIgnoreUri()
	{
		if(!$this->ignoreUri) {
			return false;
		}

		return $this->hasMatchIgnoreUri(
		    $this->request->getURI(),
            $this->request->getMethod()
        );
	}

	/**
     * Authenticates.
     *
     * @return bool
     */
	public function check()
	{
		$getter = new TokenGetter(
		    new Header($this->request),
            new  QueryStr($this->request),
            new SessionHandler($this->session, $this->jwtSessionTokenName)
        );

		return $this->auth->check($getter, $this->secretKey);
	}

    /**
     * Authenticates.
     *
     * @param array $data
     * @return bool
     */
	public function make(array $data)
	{
		$payload = array_merge($this->payload, $data);

		return $this->auth->make($payload, $this->secretKey);
	}

	/**
     * Adds a callback to the Check call
     *
     * @param callable $callback
     */
	public function onCheck($callback) 
	{
		$this->auth->onCheck($callback);
	}

	/**
     * Sets the unauthorized return
     *
     * @param callable $callback
     */
	public function onUnauthorized(callable $callback)
	{
		$this->_onUnauthorized = $callback;
	}

    /**
     * Calls the unauthorized function / callback
     *
     * @return bool return false to cancel the router
     * @throws JsonException
     */
	public function unauthorized() {
		if ($this->_onUnauthorized) {
			return call_user_func($this->_onUnauthorized, $this, $this->request, $this->response, $this->session);
		}

		$response = $this->response;
		$response->setStatusCode(401, 'Unauthorized');
		$response->setContentType("application/json");
		$response->setContent(json_encode([$this->getMessages()[0] ?? ''], JSON_THROW_ON_ERROR));

		// CORS
		if ($this->isIgnoreOptionsMethod()) {
	    	$response->setHeader("Access-Control-Allow-Origin", '*')
		      ->setHeader("Access-Control-Allow-Methods", 'GET,PUT,POST,DELETE,OPTIONS')
		      ->setHeader("Access-Control-Allow-Headers", 'Origin, X-Requested-With, Content-Range, Content-Disposition, Content-Type, Authorization')
		      ->setHeader("Access-Control-Allow-Credentials", true);
		}

		return false;
	}

	/**
     * Returns error messages
     *
     * @return array
     */
	public function getMessages()
	{
		return $this->auth->getMessages(); 
	}

	/**
     * Returns JWT payload sub or payload id.
     *
     * @return string
     */
	public function id()
	{
		return $this->auth->id();
	}

    /**
     * Returns payload or value of payload key.
     *
     * @param string $field
     * @return array|string|null
     */
	public function data(string $field = '')
	{
		return $this->auth->data($field);
	}
}
