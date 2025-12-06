<?php

/**
 * RADIUS Dynamic Authorization example CoA and Disconnect requests (RFC 5176)
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/../autoload.php';

$server = (getenv('RADIUS_SERVER_ADDR')) ?: '192.168.0.20';
$user   = (getenv('RADIUS_USER'))        ?: 'nemo';
$secret = (getenv('RADIUS_SECRET'))      ?: 'xyzzy5461';
$debug  = in_array('-v', $_SERVER['argv']);

$radius = new \Dapphp\Radius\Radius();
$radius->setServer($server)        // IP or hostname of RADIUS server
       ->setSecret($secret)        // RADIUS shared secret
       ->setDebug((bool)$debug);   // Enable debug output to screen/console

// Send a CoA-Request for a user
echo "Sending CoA request to $server with username $user\n";
$response = $radius->setNasIPAddress('10.50.1.25')
    ->setUsername($user)
    ->setAttribute('Acct-Session-Id', "A011223344556")
    ->setAttribute('Event-Timestamp', time())
    ->setVendorSpecificAttribute(\Dapphp\Radius\VendorId::MIKROTIK, 8, "0/0")
    ->setIncludeMessageAuthenticator(true)  // Include optional message authenticator
    ->coaRequest();                         // Send the CoA request

if ($response === false) {
    // false returned on failure
    echo sprintf("CoA-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    // CoA Request was accepted
    echo "Success! Received CoA-ACK from RADIUS server.\n";
}


// Send a Disconnect request
echo "Sending Disconnect-Request to $server with username $user\n";
$response = $radius->resetAttributes()
    ->setNasIPAddress('10.50.1.25')
    ->setUsername($user)
    ->setAttribute('Acct-Session-Id', "A011223344556")
    ->setAttribute('Acct-Terminate-Cause', 1)  // User request
    ->setAttribute('Event-Timestamp', time())
    ->setIncludeMessageAuthenticator(true)     // Include optional message authenticator
    ->disconnectRequest();                     // Send the disconnect request

if ($response === false) {
    // false returned on failure
    echo sprintf("Disconnect-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    // Disconnect request was accepted
    echo "Success! Received Disconnect-ACK from RADIUS server.\n";
}
