<?php

/**
 * RADIUS Accounting example (RFC 2866)
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

$nasIpAddress = '10.0.10.120';
$sessionId = 'A_S3SS10N1D';

// Start an accounting session
echo "Sending Acct-Status-Type Start to $server for username $user\n";
$response = $radius->setAttribute('Acct-Status-Type', 1)  // Start
    ->setAttribute('Acct-Session-Id', $sessionId)
    ->setAttribute('Service-Type', 2)
    ->setUsername($user)
    ->setNasIPAddress($nasIpAddress)
    ->setAttribute('NAS-Port-Type', 15)                   // Ethernet
    ->setAttribute('NAS-Port-Id', 'xe-3/5/8')
    ->accountingRequest();                                // Send the accounting request

if ($response === false) {
    // false returned on failure
    echo sprintf("Failed to start accounting: error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
    exit(1);
} else {
    // Accounting start request was accepted
    echo "Success! Accounting Started for $user (Session-ID: $sessionId).\n";
}

sleep(3);

// Send an interim update
// NOTE: The attributes set in the previous request are still set because they have not been cleared with resetAttributes()
echo "Sending Interim-Update to $server for username $user\n";
$response = $radius->setAttribute('Acct-Status-Type', 3) // Interim-Update
    ->setAttribute('Acct-Session-Time', 3)
    ->setAttribute('Acct-Input-Octets', 7500)
    ->setAttribute('Acct-Output-Octets', 13550)
    ->setAttribute('Acct-Input-Packets', 43)
    ->setAttribute('Acct-Output-Packets', 81)
    ->accountingRequest();

if ($response === false) {
    echo sprintf("Failed to send interim update: error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
    exit(1);
} else {
    echo "Interim update accepted for $user (Session-ID: $sessionId).\n";
}

sleep(3);

echo "Sending Acct-Status-Type Stop to $server for username $user\n";
$response = $radius->setAttribute('Acct-Status-Type', 2)
    ->setAttribute('Acct-Session-Time', 6)
    ->setAttribute('Acct-Input-Octets', 9600)
    ->setAttribute('Acct-Output-Octets', 19448)
    ->setAttribute('Acct-Input-Packets', 67)
    ->setAttribute('Acct-Output-Packets', 97)
    ->setAttribute('Acct-Terminate-Cause', 1) // User-Request
    ->accountingRequest();

if ($response === false) {
    echo sprintf("Failed to stop accounting: error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
    exit(1);
} else {
    echo "Accounting stopped for $user (Session-ID: $sessionId).\n";
}
