<?php

/*********************************************************************
 *
 * Pure PHP radius class
 *
 * This Radius class is a radius client implementation in pure PHP
 * following the RFC 2865 rules (http://www.ietf.org/rfc/rfc2865.txt)
 *
 * This class works with at least the following RADIUS servers:
 *  - Authenex Strong Authentication System (ASAS) with two-factor authentication
 *  - FreeRADIUS, a free Radius server implementation for Linux and *nix environments
 *  - Microsoft Radius server IAS
 *  - Mideye RADIUS server (http://www.mideye.com)
 *  - Radl, a free Radius server for Windows
 *  - RSA SecurID
 *  - VASCO Middleware 3.0 server
 *  - WinRadius, Windows Radius server (free for 5 users)
 *  - ZyXEL ZyWALL OTP (Authenex ASAS branded by ZyXEL, cheaper)
 *
 *
 * LICENCE
 *
 *   Copyright (c) 2008, SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch/)
 *   All rights reserved.
 *
 *   Copyright (c) 2016, Drew Phillips
 *   (https://drew-phillips.com)
 *
 *   This file is part of the Pure PHP radius class
 *
 *   Pure PHP radius class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 *
 *   Pure PHP radius class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Pure PHP radius class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * @author: SysCo/al
 * @author: Drew Phillips <drew@drew-phillips.com>
 * @since CreationDate: 2008-01-04
 * @copyright (c) 2008 by SysCo systemes de communication sa
 * @copyright (c) 2016 by Drew Phillips
 * @version 2.0.0
 * @link http://developer.sysco.ch/php/
 * @link developer@sysco.ch
 * @link https://github.com/dapphp/radius
 * @link drew@drew-phillips.com
 */

namespace Dapphp\Radius;

/**
 * A pure PHP RADIUS client implementation.
 *
 * Originally created by SysCo/al based on radius.class.php v1.2.2
 * Modified for PHP5 & PHP7 compatibility by Drew Phillips
 * Switched from using ext/sockets to streams.
 *
 */
class Radius
{
    protected $server;                // Radius server IP address
    protected $secret;                // Shared secret with the radius server
    protected $suffix;                // Radius suffix (default is '');
    protected $timeout;               // Timeout of the UDP connection in seconds (default value is 5)
    protected $authenticationPort;    // Authentication port (default value is 1812)
    protected $accountingPort;        // Accouting port (default value is 1813)
    protected $nasIpAddress;          // NAS IP address
    protected $nasPort;               // NAS port
    protected $encryptedPassword;     // Encrypted password, as described in the RFC 2865
    protected $requestAuthenticator;  // Request-Authenticator, 16 octets random number
    protected $responseAuthenticator; // Request-Authenticator, 16 octets random number
    protected $username;              // Username to sent to the Radius server
    protected $password;              // Password to sent to the Radius server (clear password, must be encrypted)
    protected $identifierToSend;      // Identifier field for the packet to be sent
    protected $identifierReceived;    // Identifier field for the received packet
    protected $radiusPacket;          // Radius packet code (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge, 12=Status-Server (experimental), 13=Status-Client (experimental), 255=Reserved
    protected $radiusPacketReceived;  // Radius packet code (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge, 12=Status-Server (experimental), 13=Status-Client (experimental), 255=Reserved
    protected $attributesToSend;      // Radius attributes to send
    protected $attributesReceived;    // Radius attributes received
    protected $socket;                // Socket connection
    protected $debug;                 // Debug mode flag
    protected $attributesInfo;        // Attributes info array
    protected $radiusPackets;         // Radius packet codes info array
    protected $errorCode;             // Last error code
    protected $errorMessage;          // Last error message


    public function __construct($radiusHost         = '127.0.0.1',
                                $sharedSecret       = '',
                                $radiusSuffix       = '',
                                $timeout            = 5,
                                $authenticationPort = 1812,
                                $accountingPort     = 1813)
    {
        $this->radiusPackets[1]   = 'Access-Request';
        $this->radiusPackets[2]   = 'Access-Accept';
        $this->radiusPackets[3]   = 'Access-Reject';
        $this->radiusPackets[4]   = 'Accounting-Request';
        $this->radiusPackets[5]   = 'Accounting-Response';
        $this->radiusPackets[11]  = 'Access-Challenge';
        $this->radiusPackets[12]  = 'Status-Server (experimental)';
        $this->radiusPackets[13]  = 'Status-Client (experimental)';
        $this->radiusPackets[255] = 'Reserved';

        $this->attributesInfo[1]  = array('User-Name', 'S');
        $this->attributesInfo[2]  = array('User-Password', 'S');
        $this->attributesInfo[3]  = array('CHAP-Password', 'S'); // Type (1) / Length (1) / CHAP Ident (1) / String
        $this->attributesInfo[4]  = array('NAS-IP-Address', 'A');
        $this->attributesInfo[5]  = array('NAS-Port', 'I');
        $this->attributesInfo[6]  = array('Service-Type', 'I');
        $this->attributesInfo[7]  = array('Framed-Protocol', 'I');
        $this->attributesInfo[8]  = array('Framed-IP-Address', 'A');
        $this->attributesInfo[9]  = array('Framed-IP-Netmask', 'A');
        $this->attributesInfo[10] = array('Framed-Routing', 'I');
        $this->attributesInfo[11] = array('Filter-Id', 'T');
        $this->attributesInfo[12] = array('Framed-MTU', 'I');
        $this->attributesInfo[13] = array('Framed-Compression', 'I');
        $this->attributesInfo[14] = array('Login-IP-Host', 'A');
        $this->attributesInfo[15] = array('Login-service', 'I');
        $this->attributesInfo[16] = array('Login-TCP-Port', 'I');
        $this->attributesInfo[17] = array('(unassigned)', '');
        $this->attributesInfo[18] = array('Reply-Message', 'T');
        $this->attributesInfo[19] = array('Callback-Number', 'S');
        $this->attributesInfo[20] = array('Callback-Id', 'S');
        $this->attributesInfo[21] = array('(unassigned)', '');
        $this->attributesInfo[22] = array('Framed-Route', 'T');
        $this->attributesInfo[23] = array('Framed-IPX-Network', 'I');
        $this->attributesInfo[24] = array('State', 'S');
        $this->attributesInfo[25] = array('Class', 'S');
        $this->attributesInfo[26] = array('Vendor-Specific', 'S'); // Type (1) / Length (1) / Vendor-Id (4) / Vendor type (1) / Vendor length (1) / Attribute-Specific...
        $this->attributesInfo[27] = array('Session-Timeout', 'I');
        $this->attributesInfo[28] = array('Idle-Timeout', 'I');
        $this->attributesInfo[29] = array('Termination-Action', 'I');
        $this->attributesInfo[30] = array('Called-Station-Id', 'S');
        $this->attributesInfo[31] = array('Calling-Station-Id', 'S');
        $this->attributesInfo[32] = array('NAS-Identifier', 'S');
        $this->attributesInfo[33] = array('Proxy-State', 'S');
        $this->attributesInfo[34] = array('Login-LAT-Service', 'S');
        $this->attributesInfo[35] = array('Login-LAT-Node', 'S');
        $this->attributesInfo[36] = array('Login-LAT-Group', 'S');
        $this->attributesInfo[37] = array('Framed-AppleTalk-Link', 'I');
        $this->attributesInfo[38] = array('Framed-AppleTalk-Network', 'I');
        $this->attributesInfo[39] = array('Framed-AppleTalk-Zone', 'S');
        $this->attributesInfo[60] = array('CHAP-Challenge', 'S');
        $this->attributesInfo[61] = array('NAS-Port-Type', 'I');
        $this->attributesInfo[62] = array('Port-Limit', 'I');
        $this->attributesInfo[63] = array('Login-LAT-Port', 'S');
        $this->attributesInfo[76] = array('Prompt', 'I');

        $this->identifierToSend = 0;

        $this->generateRequestAuthenticator();
        $this->setServer($radiusHost);
        $this->setSecret($sharedSecret);
        $this->setAuthenticationPort($authenticationPort);
        $this->setAccountingPort($accountingPort);
        $this->setRadiusSuffix($radiusSuffix);
        $this->setTimeout($timeout);
        $this->setUsername();
        $this->setPassword();
        $this->SetNasIpAddress();
        $this->setNasPort();

        $this->clearError();
        $this->clearDataToSend();
        $this->clearDataReceived();
    }

    public function getLastError()
    {
        if (0 < $this->errorCode) {
            return $this->errorMessage.' ('.$this->errorCode.')';
        } else {
            return '';
        }
    }

    public function setDebug($enabled = true)
    {
        $this->debug = (true === $enabled);
        return $this;
    }


    public function setServer($hostOrIp)
    {
        $this->server = gethostbyname($hostOrIp);
        return $this;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;
        return $this;
    }

    public function getSecret()
    {
        return $this->secret;
    }


    public function setRadiusSuffix($suffix)
    {
        $this->suffix = $suffix;
        return $this;
    }

    public function setUsername($username = '')
    {
        if (false === strpos($username, '@'))
        {
            $username .= $this->suffix;
        }

        $this->username = $username;
        $this->setAttribute(1, $this->username);

        return $this;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function setPassword($password = '')
    {
        $this->password    = $password;
        $encryptedPassword = '';
        $paddedPassword    = $password;

        if (0 != (strlen($password)%16)) {
            $paddedPassword .= str_repeat(chr(0), (16 - strlen($password) % 16));
        }

        $previous = $this->getRequestAuthenticator();

        for ($i = 0; $i < (strlen($paddedPassword) / 16); ++$i) {
            $temp = md5($this->getSecret() . $previous);

            $previous = '';
            for ($j = 0; $j <= 15; ++$j) {
                $value1 = ord(substr($paddedPassword, ($i * 16) + $j, 1));
                $value2 = hexdec(substr($temp, 2 * $j, 2));
                $xor_result = $value1 ^ $value2;
                $previous .= chr($xor_result);
            }
            $encryptedPassword .= $previous;
        }

        $this->encryptedPassword = $encryptedPassword;
        $this->setAttribute(2, $this->encryptedPassword);

        return $this;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function setNasIPAddress($hostOrIp = '')
    {
        if (0 < strlen($hostOrIp)) {
            $this->nasIpAddress = gethostbyname($hostOrIp);
        } else {
            $hostOrIp = @php_uname('n');
            if (empty($hostOrIp)) {
                $hostOrIp = (isset($_SERVER['HTTP_HOST'])) ? $_SERVER['HTTP_HOST'] : '';
            }
            if (empty($hostOrIp)) {
                $hostOrIp = (isset($_SERVER['SERVER_ADDR'])) ? $_SERVER['SERVER_ADDR'] : '0.0.0.0';
            }

            $this->nasIpAddress = gethostbyname($hostOrIp);
        }

        $this->setAttribute(4, $this->nasIpAddress);

        return $this;
    }

    public function getNasIPAddress()
    {
        return $this->nasIpAddress;
    }

    public function setNasPort($port = 0)
    {
        $this->nasPort = intval($port);
        $this->setAttribute(5, $this->nasPort);

        return $this;
    }

    public function getNasPort()
    {
        return $this->nasPort;
    }

    public function setTimeout($timeout = 5)
    {
        if (intval($timeout) > 0) {
            $this->timeout = intval($timeout);
        }

        return $this;
    }

    public function setAuthenticationPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536)) {
            $this->authenticationPort = intval($port);
        }

        return $this;
    }

    public function getAuthenticationPort()
    {
        return $this->authenticationPort;
    }

    public function setAccountingPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536))
        {
            $this->accountingPort = intval($port);
        }

        return $this;
    }

    public function getResponsePacket()
    {
        return $this->radiusPacketReceived;
    }


    public function getReceivedAttributes()
    {
        return $this->attributesReceived;
    }

    public function getReadableReceivedAttributes()
    {
        $attributes = '';

        if (isset($this->attributesReceived)) {
            foreach($this->attributesReceived as $receivedAttr) {
                $info = $this->getAttributesInfo($receivedAttr[0]);
                $attributes .= sprintf('%s: ', $info[0]);

                if (26 == $receivedAttr[0]) {
                    $vendorArr = $this->decodeVendorSpecificContent($receivedAttr[1]);
                    foreach($vendorArr as $vendor) {
                        $attributes .= sprintf('Vendor-Id: %s, Vendor-type: %s, Attribute-specific: %s',
                                               $vendor[0], $vendor[1], $vendor[2]);
                    }
                } else {
                    $attribues = $receivedAttr[1];
                }

                $attributes .= "<br>\n";
            }
        }

        return $attributes;
    }

    public function getAttribute($type)
    {
        $value = null;

        foreach($this->attributesReceived as $attr) {
            if (intval($type) == $attr[0]) {
                $value = $attr;
                break;
            }
        }

        return $value;
    }

    public function getRadiusPacketInfo($info_index)
    {
        if (isset($this->radiusPackets[intval($info_index)])) {
            return $this->radiusPackets[intval($info_index)];
        } else {
            return '';
        }
    }

    public function getAttributesInfo($info_index)
    {
        if (isset($this->attributesInfo[intval($info_index)])) {
            return $this->attributesInfo[intval($info_index)];
        } else {
            return array('', '');
        }
    }

    public function setAttribute($type, $value)
    {
        $index = -1;
        for ($i = 0; $i < count($this->attributesToSend); ++$i) {
            if ($type == ord(substr($this->attributesToSend[$i], 0, 1))) {
                $index = $i;
                break;
            }
        }

        $temp = null;

        if (isset($this->attributesInfo[$type])) {
            switch ($this->attributesInfo[$type][1]) {
                case 'T':
                    // Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                    $temp = chr($type) . chr(2 + strlen($value)) . $value;
                    break;
                case 'S':
                    // String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
                    $temp = chr($type) . chr(2 + strlen($value)) . $value;
                    break;
                case 'A':
                    // Address, 32 bit value, most significant octet first.
                    $ip = explode('.', $value);
                    $temp = chr($type) . chr(6) . chr($ip[0]) . chr($ip[1]) . chr($ip[2]) . chr($ip[3]);
                    break;
                case 'I':
                    // Integer, 32 bit unsigned value, most significant octet first.
                    $temp = chr($type) . chr(6) .
                            chr(($value / (256 * 256 * 256)) % 256) .
                            chr(($value / (256 * 256)) % 256) .
                            chr(($value / (256)) % 256) .
                            chr($value % 256);
                    break;
                case 'D':
                    // Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC, January 1, 1970. (not used in this RFC)
                    $temp = null;
                    break;
                default:
                    $temp = null;
            }
        }

        if ($index > -1) {
            $this->attributesToSend[$index] = $temp;
            $action = 'Modified';
        } else {
            $this->attributesToSend[] = $temp;
            $action = 'Added';
        }

        $info = $this->getAttributesInfo($type);
        $this->debugInfo("{$action} Attribute {$type} ({$info[0]}), format {$info[1]}, value <em>{$value}</em>");

        return $this;
    }

    public function resetAttributes()
    {
        $this->attributesToSend = null;
        return $this;
    }

    public function decodeVendorSpecificContent($rawValue)
    {
        $result   = array();
        $offset   = 0;
        $vendorId = (ord(substr($rawValue, 0, 1)) * 256 * 256 * 256) +
                    (ord(substr($rawValue, 1, 1)) * 256 * 256) +
                    (ord(substr($rawValue, 2, 1)) * 256) +
                     ord(substr($rawValue, 3, 1));

        $offset += 4;
        while ($offset < strlen($rawValue)) {
            $vendorType        = (ord(substr($rawValue, 0 + $offset, 1)));
            $vendorLength      = (ord(substr($rawValue, 1 + $offset, 1)));
            $attributeSpecific = substr($rawValue, 2 + $offset, $vendorLength);
            $result[]          = array($vendorId, $vendorType, $attributeSpecific);
            $offset           += $vendorLength;
        }

        return $result;
    }

    public function accessRequest($username = '', $password = '', $timeout = 0, $state = null)
    {
        $this->clearDataReceived();
        $this->clearError();

        $this->setPacketCodeToSend(1); // Access-Request

        if (0 < strlen($username)) {
            $this->setUsername($username);
        }

        if (0 < strlen($password)) {
            $this->setPassword($password);
        }

        if ($state !== null) {
            $this->setAttribute(24, $state);
        } else {
            $this->setAttribute(6, 1); // 1=Login
        }

        if (intval($timeout) > 0) {
            $this->setTimeout($timeout);
        }

        $attrContent = '';
        for ($i = 0; $i < count($this->attributesToSend); ++$i) {
            $attrContent .= $this->attributesToSend[$i];
        }

        $packet_length  = 4; // Radius packet code + Identifier + Length high + Length low
        $packet_length += strlen($this->getRequestAuthenticator()); // Request-Authenticator
        $packet_length += strlen($attrContent); // Attributes

        $packet_data  = chr($this->radiusPacket);
        $packet_data .= chr($this->getNextIdentifier());
        $packet_data .= chr(intval($packet_length/256));
        $packet_data .= chr(intval($packet_length%256));
        $packet_data .= $this->getRequestAuthenticator();
        $packet_data .= $attrContent;

        $sock = socket_create(AF_INET, SOCK_DGRAM, 17); // UDP packet = 17

        if ($sock === false) {
            $this->errorCode    = socket_last_error();
            $this->errorMessage = socket_strerror($this->errorCode);
        } elseif (false === socket_connect($sock, $this->server, $this->authenticationPort)) {
            $this->errorCode    = socket_last_error();
            $this->errorMessage = socket_strerror($this->errorCode);
        } elseif (false === socket_write($sock, $packet_data, $packet_length)) {
            $this->errorCode    = socket_last_error();
            $this->errorMessage = socket_strerror($this->errorCode);
        } else {
            $this->debugInfo(sprintf('<b>Packet type %d (%s) sent</b>', $this->radiusPacket, $this->getRadiusPacketInfo($this->radiusPacket)));
            if ($this->debug) {
                $readable_attributes = '';
                foreach($this->attributesToSend as $attr) {
                    $attr = $this->getAttributesInfo(ord(substr($attr, 0, 1)));
                    $this->debugInfo(
                        sprintf(
                            'Attribute %d (%s), length (%d), format %s, value <em>%s</em>',
                            ord(substr($attr, 0, 1)),
                            ord(substr($attr, 1, 1)) - 2,
                            $attr[1],
                            $this->decodeAttribute(substr($attr, 2), ord(substr($attr, 0, 1)))
                         )
                    );
                }
            }

            $read_socket_array   = array($sock);
            $write_socket_array  = null;
            $except_socket_array = null;

            $receivedPacket = chr(0);

            if (!(false === socket_select($read_socket_array, $write_socket_array, $except_socket_array, $this->timeout))) {
                if (in_array($sock, $read_socket_array)) {
                    if (false === ($receivedPacket = @socket_read($sock, 1024))) { // @ used, than no error is displayed if the connection is closed by the remote host
                        $receivedPacket     = chr(0);
                        $this->errorCode    = socket_last_error();
                        $this->errorMessage = socket_strerror($this->errorCode);
                    } else {
                        socket_close($sock);
                    }
                }
            } else {
                socket_close($sock);
            }
        }

        $this->radiusPacketReceived = intval(ord(substr($receivedPacket, 0, 1)));

        $this->debugInfo(sprintf(
            '<b>Packet type %d (%s) received</b>',
            $this->radiusPacketReceived,
            $this->getRadiusPacketInfo($this->getResponsePacket())
        ));

        if ($this->radiusPacketReceived > 0) {
            $this->identifierReceived = intval(ord(substr($receivedPacket, 1, 1)));
            $packet_length = (intval(ord(substr($receivedPacket, 2, 1))) * 256) + (intval(ord(substr($receivedPacket, 3, 1))));
            $this->responseAuthenticator = substr($receivedPacket, 4, 16);
            $attrContent = substr($receivedPacket, 20, ($packet_length - 4 - 16));

            while (strlen($attrContent) > 2) {
                $attrType     = intval(ord(substr($attrContent, 0, 1)));
                $attrLength   = intval(ord(substr($attrContent, 1, 1)));
                $attrValueRaw = substr($attrContent, 2, $attrLength - 2);
                $attrContent  = substr($attrContent, $attrLength);
                $attrValue    = $this->decodeAttribute($attrValueRaw, $attrType);

                $attr = $this->getAttributesInfo($attrType);
                if (26 == $attrType) {
                    $vendorArr = $this->decodeVendorSpecificContent($attrValue);
                    foreach($vendorArr as $vendor) {
                        $this->debugInfo(
                            sprintf(
                                'Attribute %d (%s), length %d, format %s, Vendor-Id: %d, Vendor-type: %s, Attribute-specific: %s',
                                $attrType, $attr[0], $attrLength - 2,
                                $attr[1], $vendor[0], $vendor[1], $vendor[2]
                            )
                        );
                    }
                } else {
                    $this->debugInfo(
                        sprintf(
                            'Attribute %d (%s), length %d, format %s, value <em>%s</em>',
                            $attrType, $attr[0], $attrLength - 2, $attr[1], $attrValue
                        )
                    );
                }

                $this->attributesReceived[] = array($attrType, $attrValue);
            }
        }

        return (2 == ($this->radiusPacketReceived));
    }

    protected function getNextIdentifier()
    {
        $this->identifierToSend = (($this->identifierToSend + 1) % 256);
        return $this->identifierToSend;
    }

    protected function generateRequestAuthenticator()
    {
        $this->requestAuthenticator = '';

        for ($c = 0; $c <= 15; ++$c) {
            $this->requestAuthenticator .= chr(rand(1, 255));
        }

        return $this;
    }

    protected function getRequestAuthenticator()
    {
        return $this->requestAuthenticator;
    }

    protected function clearDataToSend()
    {
        $this->radiusPacket     = 0;
        $this->attributesToSend = null;
        return $this;
    }

    protected function clearDataReceived()
    {
        $this->radiusPacketReceived = 0;
        $this->attributesReceived   = null;
        return $this;
    }

    protected function setPacketCodeToSend($packet_code)
    {
        $this->radiusPacket = $packet_code;
        return $this;
    }

    protected function clearError()
    {
        $this->errorCode    = 0;
        $this->errorMessage = '';

        return $this;
    }

    protected function debugInfo($message)
    {
        if ($this->debug) {
            echo date('Y-m-d H:i:s').' DEBUG: ';
            echo $message;
            echo "<br />\n";
            flush();
        }
    }

    protected function decodeAttribute($rawValue, $attributeFormat)
    {
        $value = null;

        if (isset($this->attributesInfo[$attributeFormat])) {
            switch ($this->attributesInfo[$attributeFormat][1]) {
                case 'T':
                    $value = $rawValue;
                    break;
                case 'S':
                    $value = $rawValue;
                    break;
                case 'A':
                    $value = ord(substr($rawValue, 0, 1)) . '.' .
                             ord(substr($rawValue, 1, 1)) . '.' .
                             ord(substr($rawValue, 2, 1)) . '.' .
                             ord(substr($rawValue, 3, 1));
                    break;
                case 'I':
                    $value = (ord(substr($rawValue, 0, 1)) * 256 * 256 * 256) +
                             (ord(substr($rawValue, 1, 1)) *256 * 256) +
                             (ord(substr($rawValue, 2, 1)) *256) +
                              ord(substr($rawValue, 3, 1));
                    break;
                case 'D':
                    $value = null;
                    break;
                default:
                    $value = null;
            }
        }

        return $value;
    }
}
