<?php

/**
 * RADIUS client example using EAP-MS-CHAP-V2.
 *
 * Tested on Windows Server 2012 R2, 2016, and 2019 Standard Network Policy Server.
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
$radius->setServer($server)            // IP or hostname of RADIUS server
       ->setSecret($secret)            // RADIUS shared secret
       ->setAttribute(32, 'login')               // NAS port
       ->setDebug((bool)$debug);

// Send access request for user nemo
echo "Sending EAP-MSCHAP-v2 access request to $server with username $user\n";
$response = $radius->accessRequestEapMsChapV2($user, $pass);

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
