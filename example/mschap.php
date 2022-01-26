<?php

/**
 * RADIUS client example using MS-CHAPv1.
 *
 * Tested with Windows Server 2012 R2 Network Policy Server
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/../autoload.php';

$server = (getenv('RADIUS_SERVER_ADDR')) ?: '192.168.0.20';
$user   = (getenv('RADIUS_USER'))        ?: 'nemo';
$pass   = (getenv('RADIUS_PASS'))        ?: 'arctangent';
$secret = (getenv('RADIUS_SECRET'))      ?: 'xyzzy5461';
$debug  = in_array('-v', $_SERVER['argv']);

$radius = new \Dapphp\Radius\Radius();
$radius->setServer($server)     // IP or hostname of RADIUS server
       ->setSecret($secret)        // RADIUS shared secret
       ->setNasIpAddress('127.0.0.1')  // IP or hostname of NAS (device authenticating user)
       ->setNasPort(20)                   // NAS port
       ->setDebug((bool)$debug);

$radius->setMSChapPassword($pass); // set mschapv1 password for user

// Send access request for user nemo
echo "Sending MS-CHAP access request to $server with username $user\n";
$response = $radius->accessRequest($user);

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
