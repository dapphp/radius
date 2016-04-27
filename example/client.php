<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/../src/Radius.php';

$radius = new \Dapphp\Radius\Radius();
$radius->setServer('127.0.0.1')        // IP or hostname of RADIUS server
       ->setSecret('testing123')       // RADIUS shared secret
       ->setNasIpAddress('127.0.0.1')  // IP or hostname of NAS (device authenticating user)
       ->setAttribute(32, 'vpn')       // NAS identifier
       ->setDebug();                   // Enable debug output to screen/console

// Send access request for user with password mys3cr3t
$response = $radius->accessRequest('drew010', 'mys3cr3t');

if ($response === false) {
    // false returned on failure
    echo sprintf("Access-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    // access request was accepted - client authenticated successfully
    echo "Success!  Received Access-Accept response from RADIUS server.\n";
}

