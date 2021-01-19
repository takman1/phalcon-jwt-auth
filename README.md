# phalcon-jwt-auth

A simple JWT middleware for Phalcon to handle stateless authentication or session based token.

## Installation
```bash
$ composer require takman1/phalcon-jwt-auth
```

## Usage

### Configuration
In main config or module config
```php
<?php

use Phalcon\Config;

/** @var Config $config */
return $config->merge(new Config([
    'myapi-auth' => [
        'secretKey' => $_SERVER['API_JWT_SECRET_KEY'], // secretKey comes from .env file (or ENV variables)
        'session-token-name' => 'myapi-jwt-token', // token name in session
        'payload' => [
            'exp' => 10, // in minutes
            'iss' => 'myapi-jwt-auth'
        ],
        'ignoreUri' => [
            '/',
            '/api',
            '/api/login',
            '/api/logout',
        ]
    ]
]));

```


in bootstrap or index file
```php
$di->setShared(
    'dispatcher',
    function () use ($di) {
        /** @var \Phalcon\Events\ManagerInterface $eventsManager */
        $eventsManager = $di->getShared('eventsManager');
        $eventsManager->attach(
            'dispatch:beforeExecuteRoute', //plug the service to this event
            function (\Phalcon\Events\Event $event, $dispatcher) {
                return $dispatcher->getDi()
                    ->getShared('jwtAuth') // service declared bellow
                    ->beforeExecuteRoute($event, $dispatcher);
            }
        );

        $dispatcher = new \Phalcon\Mvc\Dispatcher();
        $dispatcher->setEventsManager($eventsManager);
        $dispatcher->setDefaultNamespace('App\Api\Controller');

        return $dispatcher;
    }
);

$di->setShared('jwtAuth', function () use ($di) {
    return new \Dmkit\Phalcon\Auth\Middleware\JwtAuthenticator(
        $di->get('request'),
        $di->get('response'),
        $di->get('session'),
        $di->getConfig(),
        'myapi-auth' //config key
    );
});
```


### Authentication
To make authenticated requests via http, you will need to set an authorization headers as follows:
```
Authorization: Bearer {yourtokenhere}
```
or pass the token as a query string
```
?_token={yourtokenhere}
```
or set token in session
```php
public function myAction()
{
    // get token from session
    $tokenName = $this->config->get('myapi-auth')->get('session-token-name');
    $tokenValue = $this->session->get($tokenName);

    // set token and its payload in session
    // array of payload data, to customize 
    $payload = [
        'username' => $username,
        'password' => $password,
        'role' => 'api-user',
        'iat' => time(),
    ];
    // jwtAuth is the service name
    $token = $this->jwtAuth->make($payload);
    $this->session->set($tokenName, $token);
    
    // disconnect user by unsetting the token in session
    $this->session->remove($this->config->get('myapi-auth')->get('session-token-name'));
    
    //get payload data
    // in controller
    $this->jwtAuth->data(); // all data array
    $this->jwtAuth->data('username'); // get specific "username" data
    // in another service
    \Phalcon\Di::getDefault()->get('jwtAuth')->data();
}
```

### Callbacks

By default if the authentication fails, the middleware will stop the execution of routes and will immediately return a response of 401 Unauthorized. If you want to add your own handler:
```php
$auth->onUnauthorized(function($auth, $request, $response, $session) {

    $response->setStatusCode(401, 'Unauthorized');
    $response->setContentType("application/json");

    // to get the error messages
    $response->setContent(json_encode([$auth->getMessages()[0] ?? '']));

    // return false to stop the execution
    return false;
});
```

If you want an additional checking on the authentication, like intentionally expiring a token based on the payload issued date, you may do so:
```php
$auth->onCheck(function($auth) {
    // to get the payload
    $data = $auth->data();
    
    if ($data['iat'] <= strtotime('-1 day')) {
        // return false to invalidate the authentication
        return false;
    }

});
```

### The Auth service

You can access the middleware by calling the "auth" service.
```php
print_r($di->get('auth')->data());

print_r($app->getDI()->get('auth')->data('email'));

// in your controller
print_r($this->auth->data());
```

### Accessing the authenticated user / data
In your controller or route handler
```php
echo $this->auth->id(); // will look for sub or id payload

echo $this->auth->data(); // return all payload

echo $this->auth->data('email');
```

### Original project
This project is forked and based on dmkit/phalcon-jwt-auth : https://github.com/dmkit/phalcon-jwt-auth
