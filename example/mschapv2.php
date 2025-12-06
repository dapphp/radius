<?php

/**
 * RADIUS client example using MS-CHAP-V2 (non-EAP).
 *
 * Tested on Windows Server 2012 R2, 2016, 2019 Standard Network Policy Server, and FreeRadius 3.2
 *
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
$radius->setServer($server)                // IP or hostname of RADIUS server
       ->setSecret($secret)                // RADIUS shared secret
       ->setNasIpAddress('192.168.88.66')  // IP or hostname of NAS (device authenticating user)
       ->setIncludeMessageAuthenticator(true)
       ->setDebug((bool)$debug)
       ->setUsername($user)                // Set the username
       ->setMsChapV2Password($user, $pass) // Add the MS-CHAP-Challenge and MS-CHAP2-Response to the request
;

// Send access request using MS-CHAP-V2 for user nemo
$response = $radius->accessRequest();

if ($response === false) {
    // false returned on failure
    echo sprintf("Access-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    // access request was accepted - client authenticated successfully
    echo "Success!  Received Access-Accept response from RADIUS server.\n";

    if (!empty($reply = $radius->getReceivedAttribute('Reply-Message'))) {
        echo "Reply-Message: $reply\n";
    }
}
