<?php

/*********************************************************************
 *
 * Pure PHP radius class
 *
 * This Radius class is a radius client implementation in pure PHP
 * following the RFC 2865 rules (http://www.ietf.org/rfc/rfc2865.txt)
 *
 * It also can be used for RFC 3576 dynamic authorization extensions
 * to radius.
 *
 * This class works with at least the following RADIUS servers:
 *  - Authenex Strong Authentication System (ASAS) with two-factor authentication
 *  - FreeRADIUS, a free Radius server implementation for Linux and *nix environments
 *  - Microsoft Radius server IAS
 *  - Microsoft Windows Server 2016 (Network Policy Server)
 *  - Microsoft Windows Server 2012 R2 (Network Policy Server)
 *  - Microsoft Windows Server 2019 Standard (Network Policy Server)
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
 *   Copyright (c) 2016-2026, Drew Phillips
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
 * @license LGPL-3.0-or-later
 * @since CreationDate: 2008-01-04
 * @copyright (c) 2008 by SysCo systemes de communication sa
 * @copyright (c) 2016-2026 by Drew Phillips
 * @link https://github.com/dapphp/radius
 * @link drew@drew-phillips.com
 * @link http://developer.sysco.ch/php/
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
    /** @var int Access-Request packet type identifier */
    const TYPE_ACCESS_REQUEST      = 1;

    /** @var int Access-Accept packet type identifier */
    const TYPE_ACCESS_ACCEPT       = 2;

    /** @var int Access-Reject packet type identifier */
    const TYPE_ACCESS_REJECT       = 3;

    /** @var int Accounting-Request packet type identifier */
    const TYPE_ACCOUNTING_REQUEST  = 4;

    /** @var int Accounting-Response packet type identifier */
    const TYPE_ACCOUNTING_RESPONSE = 5;

    /** @var int Access-Challenge packet type identifier */
    const TYPE_ACCESS_CHALLENGE    = 11;

    /** @var int Disconnect-Request packet type identifier */
    const TYPE_DISCONNECT_REQUEST  = 40;

    /** @var int Disconnect-ACK packet type identifier */
    const TYPE_DISCONNECT_ACK      = 41;

    /** @var int Disconnect-NAK packet type identifier */
    const TYPE_DISCONNECT_NAK      = 42;

    /** @var int CoA-Request packet type identifier */
    const TYPE_COA_REQUEST         = 43;

    /** @var int CoA-ACK packet type identifier */
    const TYPE_COA_ACK             = 44;

    /** @var int CoA-NAK packet type identifier */
    const TYPE_COA_NAK             = 45;

    /** @var int Reserved packet type */
    const TYPE_RESERVED            = 255;

    /** @var string If calling generateRadiusPacket() directly for regular RADIUS requests, sets the Authenticator in
     * the packet header to random bytes
     */
    const AUTH_REQUEST = 'request';

    /** @var string If calling generateRadiusPacket() directly for Accounting requests, zero out Authenticator, compute
     * MD5 over packet + secret
     */
    const AUTH_ACCOUNTING = 'accounting';

    // RFC 8044 RADIUS data type constants

    const DATA_TYPE_INTEGER = 'integer';
    const DATA_TYPE_ENUM = 'enum';
    const DATA_TYPE_TIME = 'time';
    const DATA_TYPE_TEXT = 'text';
    const DATA_TYPE_STRING = 'string';
    const DATA_TYPE_CONCAT = 'concat';
    const DATA_TYPE_IFID = 'ifid';
    const DATA_TYPE_IPV4ADDR = 'ipv4addr';
    const DATA_TYPE_IPV6ADDR = 'ipv6addr';
    const DATA_TYPE_IPV6PREFIX = 'ipv6prefix';
    const DATA_TYPE_IPV4PREFIX = 'ipv4prefix';
    const DATA_TYPE_INTEGER64 = 'integer64';
    const DATA_TYPE_TLV = 'tlv';
    const DATA_TYPE_VSA = 'vsa';
    const DATA_TYPE_EXTENDED = 'extended';
    const DATA_TYPE_LONG_EXTENDED = 'long-extended';
    const DATA_TYPE_LONG_EVS = 'evs';

    // Class properties

    /** @var string RADIUS server hostname or IP address */
    protected $server;

    /** @var string Shared secret with the RADIUS server */
    protected $secret = '';

    /** @var string RADIUS suffix (default is '') */
    protected $suffix = '';

    /** @var int Timeout for receiving UDP response packets (default = 5 seconds) */
    protected $timeout = 5;

    /** @var int Authentication port (default = 1812) */
    protected $authenticationPort = 1812;

    /** @var int Accounting port (default = 1813) */
    protected $accountingPort = 1813;

    /** @var int Dynamic Authorization Port for RFC 5176 CoA and Disconnect requests (default = 3799) */
    protected $dynamicAuthorizationPort = 3799;

    /** @var string Network Access Server (client) IP Address */
    protected $nasIpAddress;

    /** @var string NAS port. Physical port of the NAS authenticating the user */
    protected $nasPort;


    /** @var int Request-Authenticator, 16 octets random number */
    protected $requestAuthenticator;

    /** @var int Request-Authenticator from the response */
    protected $responseAuthenticator;

    /** @var string Username to send to the RADIUS server */
    protected $username = '';

    /** @var string Password for authenticating with the RADIUS server (before encryption) */
    protected $password;

    /** @var int The CHAP identifier for CHAP-Password attributes */
    protected $chapIdentifier;

    /** @var int Identifier field for the packet to be sent */
    protected $identifierToSend = -1;

    /** @var string Identifier field for the received packet */
    protected $identifierReceived;

    /** @var int RADIUS packet type (1=Access-Request, 2=Access-Accept, etc) */
    protected $radiusPacket = 0;

    /** @var int Packet type received in response from RADIUS server */
    protected $radiusPacketReceived = 0;

    /** @var array List of RADIUS attributes to send */
    protected $attributesToSend = [];

    /** @var array List of attributes received in response */
    protected $attributesReceived = [];

    /** @var bool Whether or not to enable debug output */
    protected $debug = false;

    /** @var array RADIUS attributes info array */
    protected $attributesInfo = [];

    /** @var array Mapping of RADIUS attribute names to numbers */
    protected $attributesNamesMap = [];

    /** @var array RADIUS packet codes info array */
    protected $radiusPackets;

    /** @var int The error code from the last operation */
    protected $errorCode = 0;

    /** @var string The error message from the last operation */
    protected $errorMessage = '';

    /** @var string[] Data types for encoding attributes - RFC 8044 */
    protected $radiusDataTypes = [
        1 => self::DATA_TYPE_INTEGER,
        2 => self::DATA_TYPE_ENUM,
        3 => self::DATA_TYPE_TIME,
        4 => self::DATA_TYPE_TEXT,
        5 => self::DATA_TYPE_STRING,
        6 => self::DATA_TYPE_CONCAT,
        7 => self::DATA_TYPE_IFID,
        8 => self::DATA_TYPE_IPV4ADDR,
        9 => self::DATA_TYPE_IPV6ADDR,
        10 => self::DATA_TYPE_IPV6PREFIX,
        11 => self::DATA_TYPE_IPV4PREFIX,
        12 => self::DATA_TYPE_INTEGER64,
        13 => self::DATA_TYPE_TLV,
        14 => self::DATA_TYPE_VSA,
        15 => self::DATA_TYPE_EXTENDED,
        16 => self::DATA_TYPE_LONG_EXTENDED,
        17 => self::DATA_TYPE_LONG_EVS,
    ];

    /** @var int[] Map of old data type identifiers to $radiusDataTypes */
    protected $dataTypeMap = [
        'I' => 1,
        'D' => 3,
        'T' => 4,
        'S' => 5,
        'A' => 8,
        // no other types were defined in earlier versions
    ];


    /**
     * Radius constructor.
     *
     * @param string $radiusHost          The RADIUS server hostname or IP address
     * @param string $sharedSecret        The RADIUS server shared secret
     * @param string $radiusSuffix        The username suffix to use when authenticating
     * @param int $timeout                The timeout (in seconds) to wait for RADIUS responses
     * @param int $authenticationPort     The port for authentication requests (default = 1812)
     * @param int $accountingPort         The port for accounting requests (default = 1813)
     */
    public function __construct($radiusHost         = '127.0.0.1',
                                $sharedSecret       = '',
                                $radiusSuffix       = '',
                                $timeout            = 5,
                                $authenticationPort = 1812,
                                $accountingPort     = 1813)
    {
        $this->radiusPackets      = array();
        $this->radiusPackets[1]   = 'Access-Request';
        $this->radiusPackets[2]   = 'Access-Accept';
        $this->radiusPackets[3]   = 'Access-Reject';
        $this->radiusPackets[4]   = 'Accounting-Request';
        $this->radiusPackets[5]   = 'Accounting-Response';
        $this->radiusPackets[11]  = 'Access-Challenge';
        $this->radiusPackets[12]  = 'Status-Server (experimental)';
        $this->radiusPackets[13]  = 'Status-Client (experimental)';
        $this->radiusPackets[40]  = 'Disconnect-Request';
        $this->radiusPackets[41]  = 'Disconnect-ACK';
        $this->radiusPackets[42]  = 'Disconnect-NAK';
        $this->radiusPackets[43]  = 'CoA-Request';
        $this->radiusPackets[44]  = 'CoA-ACK';
        $this->radiusPackets[45]  = 'CoA-NAK';
        $this->radiusPackets[255] = 'Reserved';

        $this->initDefaultAttributes();

        $this->identifierToSend = -1;
        $this->chapIdentifier   = 1;

        if (!empty($radiusHost)) {
            $this->setServer($radiusHost);
        }
        if (!empty($sharedSecret)) {
            $this->setSecret($sharedSecret);
        }
        if (!empty($radiusSuffix)) {
            $this->setRadiusSuffix($radiusSuffix);
        }

        $this->generateRequestAuthenticator()
             ->setAuthenticationPort($authenticationPort)
             ->setAccountingPort($accountingPort)
             ->setTimeout($timeout);

        $this->clearError()
             ->clearDataToSend()
             ->clearDataReceived();
    }

    /*
     * Initialize the default RADIUS attributes known to the object.
     * Includes all attributes from the following RFCs:
     * - RFC 2865: RADIUS (S) 5. Attributes
     * - RFC 2866: RADIUS Accounting (S) 5. Attributes
     * - RFC 2867: RADIUS Accounting Modifications for Tunnel Protocol Support (S) 4. Attributes
     * - RFC 2868: RADIUS Attributes for Tunnel Protocol Support (S) 3. Attributes
     * - RFC 2869: RADIUS Extensions (S) 5. Attributes
     * - RFC 3162: RADIUS and IPv6
     * - RFC 4675: RADIUS Attributes for Virtual LAN and Priority Support (S) 2. Attributes
     * - RFC 4849: RADIUS Filter Rule Attribute
     */
    private function initDefaultAttributes()
    {
        $this->attributesInfo = [];

        // RFC 2865
        $this->attributesInfo[1]  = [ 'User-Name', 'T' ];
        $this->attributesInfo[2]  = [ 'User-Password', 'S' ];;
        $this->attributesInfo[3]  = [ 'CHAP-Password', 'S' ]; // Type (1) / Length (1) / CHAP Ident (1) / String
        $this->attributesInfo[4]  = [ 'NAS-IP-Address', 'A' ];
        $this->attributesInfo[5]  = [ 'NAS-Port', 'I' ];
        $this->attributesInfo[6]  = [ 'Service-Type', 'I' ];
        $this->attributesInfo[7]  = [ 'Framed-Protocol', 'I' ];
        $this->attributesInfo[8]  = [ 'Framed-IP-Address', 'A' ];
        $this->attributesInfo[9]  = [ 'Framed-IP-Netmask', 'A' ];
        $this->attributesInfo[10] = [ 'Framed-Routing', 'I' ];
        $this->attributesInfo[11] = [ 'Filter-Id', 'T' ];
        $this->attributesInfo[12] = [ 'Framed-MTU', 'I' ];
        $this->attributesInfo[13] = [ 'Framed-Compression', 'I' ];
        $this->attributesInfo[14] = [ 'Login-IP-Host', 'A' ];
        $this->attributesInfo[15] = [ 'Login-service', 'I' ];
        $this->attributesInfo[16] = [ 'Login-TCP-Port', 'I' ];
        // 17 = unassigned
        $this->attributesInfo[18] = [ 'Reply-Message', 'T' ];
        $this->attributesInfo[19] = [ 'Callback-Number', 'T' ];
        $this->attributesInfo[20] = [ 'Callback-Id', 'T' ];
        // 21 = unassigned
        $this->attributesInfo[22] = [ 'Framed-Route', 'T' ];
        $this->attributesInfo[23] = [ 'Framed-IPX-Network', 'I' ];
        $this->attributesInfo[24] = [ 'State', 'S' ];
        $this->attributesInfo[25] = [ 'Class', 'S' ];
        $this->attributesInfo[26] = [ 'Vendor-Specific', 'vsa' ]; // Type (1) / Length (1) / Vendor-Id (4) / Vendor type (1) / Vendor length (1) / Attribute-Specific...
        $this->attributesInfo[27] = [ 'Session-Timeout', 'I' ];
        $this->attributesInfo[28] = [ 'Idle-Timeout', 'I' ];
        $this->attributesInfo[29] = [ 'Termination-Action', 'I' ];
        $this->attributesInfo[30] = [ 'Called-Station-Id', 'S' ];
        $this->attributesInfo[31] = [ 'Calling-Station-Id', 'S' ];
        $this->attributesInfo[32] = [ 'NAS-Identifier', 'S' ];
        $this->attributesInfo[33] = [ 'Proxy-State', 'S' ];
        $this->attributesInfo[34] = [ 'Login-LAT-Service', 'S' ];
        $this->attributesInfo[35] = [ 'Login-LAT-Node', 'S' ];
        $this->attributesInfo[36] = [ 'Login-LAT-Group', 'S' ];
        $this->attributesInfo[37] = [ 'Framed-AppleTalk-Link', 'I' ];
        $this->attributesInfo[38] = [ 'Framed-AppleTalk-Network', 'I' ];
        $this->attributesInfo[39] = [ 'Framed-AppleTalk-Zone', 'S' ];

        // RFC 2866
        $this->attributesInfo[40] = [ 'Acct-Status-Type', 'I' ];
        $this->attributesInfo[41] = [ 'Acct-Delay-Time', 'I' ];
        $this->attributesInfo[42] = [ 'Acct-Input-Octets', 'I' ];
        $this->attributesInfo[43] = [ 'Acct-Output-Octets', 'I' ];
        $this->attributesInfo[44] = [ 'Acct-Session-Id', 'S' ];
        $this->attributesInfo[45] = [ 'Acct-Authentic', 'I' ];
        $this->attributesInfo[46] = [ 'Acct-Session-Time', 'I' ];
        $this->attributesInfo[47] = [ 'Acct-Input-Packets', 'I' ];
        $this->attributesInfo[48] = [ 'Acct-Output-Packets', 'I' ];
        $this->attributesInfo[49] = [ 'Acct-Terminate-Cause', 'I' ];
        $this->attributesInfo[50] = [ 'Acct-Multi-Session-Id', 'S' ];
        $this->attributesInfo[51] = [ 'Acct-Link-Count', 'I' ];

        // RFC 2869
        $this->attributesInfo[52] = [ 'Acct-Input-Gigawords', 'I' ];
        $this->attributesInfo[53] = [ 'Acct-Output-Gigawords', 'I' ];
        // 54 = Unassigned
        $this->attributesInfo[55] = [ 'Event-Timestamp', 'I' ];

        // RFC 4675
        $this->attributesInfo[56] = [ 'Egress-VLANID', 'I' ];
        $this->attributesInfo[57] = [ 'Ingress-Filters', 'I' ];
        $this->attributesInfo[58] = [ 'Egress-VLAN-Name', 'S' ];
        $this->attributesInfo[59] = [ 'User-Priority-Table', 'S' ];

        // RFC 2865
        $this->attributesInfo[60] = [ 'CHAP-Challenge', 'S' ];
        $this->attributesInfo[61] = [ 'NAS-Port-Type', 'I' ];
        $this->attributesInfo[62] = [ 'Port-Limit', 'I' ];
        $this->attributesInfo[63] = [ 'Login-LAT-Port', 'S' ];

        // RFC 2868
        $this->attributesInfo[64] = [ 'Tunnel-Type', 'S' ];
        $this->attributesInfo[65] = [ 'Tunnel-Medium-Type', 'S' ];
        $this->attributesInfo[66] = [ 'Tunnel-Client-Endpoint', 'S' ];
        $this->attributesInfo[67] = [ 'Tunnel-Server-Endpoint', 'S' ];

        // RFC 2867
        $this->attributesInfo[68] = [ 'Acct-Tunnel-Connection', 'S' ];

        // RFC 2868
        $this->attributesInfo[69] = [ 'Tunnel-Password', 'S' ];

        // RFC 2869
        $this->attributesInfo[70] = [ 'ARAP-Password', 'S' ];
        $this->attributesInfo[71] = [ 'ARAP-Features', 'S' ];
        $this->attributesInfo[72] = [ 'ARAP-Zone-Access', 'I' ];
        $this->attributesInfo[73] = [ 'ARAP-Security', 'I' ];
        $this->attributesInfo[74] = [ 'ARAP-Security-Data', 'S' ];
        $this->attributesInfo[75] = [ 'Password-Retry', 'I' ];
        $this->attributesInfo[76] = [ 'Prompt', 'I' ];
        $this->attributesInfo[77] = [ 'Connect-Info', 'S' ];
        $this->attributesInfo[78] = [ 'Configuration-Token', 'S' ];
        $this->attributesInfo[79] = [ 'EAP-Message', 'concat' ];
        $this->attributesInfo[80] = [ 'Message-Authenticator', 'S' ];

        // RFC 2868
        $this->attributesInfo[81] = [ 'Tunnel-Private-Group-ID', 'T' ];
        $this->attributesInfo[82] = [ 'Tunnel-Assignment-ID', 'T' ];
        $this->attributesInfo[83] = [ 'Tunnel-Preference', 'I' ];

        // RFC 2869
        $this->attributesInfo[84] = [ 'ARAP-Challenge-Response', 'S' ];
        $this->attributesInfo[85] = [ 'Acct-Interim-Interval', 'I' ];

        // RFC 2867
        $this->attributesInfo[86] = [ 'Acct-Tunnel-Packets-Lost', 'I' ];

        // RFC 2869
        $this->attributesInfo[87] = [ 'NAS-Port-Id', 'T' ];
        $this->attributesInfo[88] = [ 'Framed-Pool', 'T' ];

        // RFC 2868
        $this->attributesInfo[90] = [ 'Tunnel-Client-Auth-ID', 'T' ];
        $this->attributesInfo[91] = [ 'Tunnel-Server-Auth-ID', 'T' ];

        // RFC 4849
        $this->attributesInfo[92] = [ 'NAS-Filter-Rule', 'T' ];

        // 93 = unassigned

        // RFC 7155
        $this->attributesInfo[94] = [ 'Originating-Line-Info', 'S' ];

        // RFC 3162
        $this->attributesInfo[95] = [ 'NAS-IPv6-Address', 'ipv6addr' ];
        $this->attributesInfo[96] = [ 'Framed-Interface-Id', 'ifid' ];
        $this->attributesInfo[97] = [ 'Framed-IPv6-Prefix', 'ipv6prefix' ];
        $this->attributesInfo[98] = [ 'Login-IPv6-Host', 'ipv6addr' ];
        $this->attributesInfo[99] = [ 'Framed-IPv6-Route', 'T' ];
        $this->attributesInfo[100] = [ 'Framed-IPv6-Pool', 'T' ];

        // RFC 3576 / 5176
        $this->attributesInfo[101] = [ 'Error-Cause Attribute', 'I' ];

        // RFC 4072 / RFC 7268
        $this->attributesInfo[102] = [ 'EAP-Key-Name', 'text' ];

        // RFC 5090
        $this->attributesInfo[103] = [ 'Digest-Response', 'text' ];
        $this->attributesInfo[104] = [ 'Digest-Realm', 'text' ];
        $this->attributesInfo[105] = [ 'Digest-Nonce', 'text' ];
        $this->attributesInfo[106] = [ 'Digest-Response-Auth', 'text' ];
        $this->attributesInfo[107] = [ 'Digest-Nextnonce', 'text' ];
        $this->attributesInfo[108] = [ 'Digest-Method', 'text' ];
        $this->attributesInfo[109] = [ 'Digest-URI', 'text' ];
        $this->attributesInfo[110] = [ 'Digest-Qop', 'text' ];
        $this->attributesInfo[111] = [ 'Digest-Algorithm', 'text' ];
        $this->attributesInfo[112] = [ 'Digest-Entity-Body-Hash', 'text' ];
        $this->attributesInfo[113] = [ 'Digest-CNonce', 'text' ];
        $this->attributesInfo[114] = [ 'Digest-Nonce-Count', 'text' ];
        $this->attributesInfo[115] = [ 'Digest-Username', 'text' ];
        $this->attributesInfo[116] = [ 'Digest-Opaque', 'text' ];
        $this->attributesInfo[117] = [ 'Digest-Auth-Param', 'text' ];
        $this->attributesInfo[118] = [ 'Digest-AKA-Auts', 'text' ];
        $this->attributesInfo[119] = [ 'Digest-Domain', 'text' ];
        $this->attributesInfo[120] = [ 'Digest-Stale', 'text' ];
        $this->attributesInfo[121] = [ 'Digest-HA1', 'text' ];
        $this->attributesInfo[122] = [ 'SIP-AOR', 'text' ];

        // RFC 4818
        $this->attributesInfo[123] = [ 'Delegated-IPv6-Prefix', 'ipv6prefix' ];

        // RFC 5447
        $this->attributesInfo[124] = [ 'MIP6-Feature-Vector', 'integer64' ];
        $this->attributesInfo[125] = [ 'MIP6-Home-Link-Prefix', 'S' ];

        // RFC 5880
        $this->attributesInfo[126] = [ 'Operator-Name', 'text' ];
        $this->attributesInfo[127] = [ 'Location-Information', 'S' ];
        $this->attributesInfo[128] = [ 'Location-Data', 'S' ];
        $this->attributesInfo[129] = [ 'Basic-Location-Policy-Rules', 'S' ];
        $this->attributesInfo[130] = [ 'Extended-Location-Policy-Rules', 'S' ];
        $this->attributesInfo[131] = [ 'Location-Capable', 'enum' ];
        $this->attributesInfo[132] = [ 'Requested-Location-Info', 'enum'];

        // RFC 5607
        $this->attributesInfo[133] = [ 'Framed-Management-Protocol', 'enum'];
        $this->attributesInfo[134] = [ 'Management-Transport-Protection', 'enum' ];
        $this->attributesInfo[135] = [ 'Management-Policy-Id', 'text' ];
        $this->attributesInfo[136] = [ 'Management-Privilege-Level', 'I' ];

        // RFC 5904
        $this->attributesInfo[137] = [ 'PKM-SS-Cert', 'concat' ];
        $this->attributesInfo[138] = [ 'PKM-CA-Cert', 'concat' ];
        $this->attributesInfo[139] = [ 'PKM-Config-Settings', 'S' ];
        $this->attributesInfo[140] = [ 'PKM-Cryptosuite-List', 'S' ];
        $this->attributesInfo[141] = [ 'PKM-SAID', 'text' ];
        $this->attributesInfo[142] = [ 'PKM-SA-Descriptor', 'S' ];
        $this->attributesInfo[143] = [ 'PKM-Auth-Key', 'S' ];

        // RFC 6519
        $this->attributesInfo[144] = [ 'DS-Lite-Tunnel-Name', 'S' ];

        // RFC 6572
        $this->attributesInfo[145] = [ 'Mobile-Node-Identifier', 'S' ];
        $this->attributesInfo[146] = [ 'Service-Selection', 'text' ];
        $this->attributesInfo[147] = [ 'PMIP6-Home-LMA-IPv6-Address', 'ipv6addr' ];
        $this->attributesInfo[148] = [ 'PMIP6-Visited-LMA-IPv6-Address', 'ipv6addr' ];
        $this->attributesInfo[149] = [ 'PMIP6-Home-LMA-IPv4-Address', 'ipv4addr' ];
        $this->attributesInfo[150] = [ 'PMIP6-Visited-LMA-IPv4-Address', 'ipv4addr' ];
        $this->attributesInfo[151] = [ 'PMIP6-Home-HN-Prefix', 'ipv6prefix' ];
        $this->attributesInfo[152] = [ 'PMIP6-Visited-HN-Prefix', 'ipv6prefix' ];
        $this->attributesInfo[153] = [ 'PMIP6-Home-Interface-ID', 'ifid' ];
        $this->attributesInfo[154] = [ 'PMIP6-Visited-Interface-ID', 'ifid' ];
        $this->attributesInfo[155] = [ 'PMIP6-Home-IPv4-HoA', 'ipv4prefix' ];
        $this->attributesInfo[156] = [ 'PMIP6-Visited-IPv4-HoA', 'ipv4prefix' ];
        $this->attributesInfo[157] = [ 'PMIP6-Home-DHCP4-Server-Address', 'ipv4addr' ];
        $this->attributesInfo[158] = [ 'PMIP6-Visited-DHCP4-Server-Address', 'ipv4addr' ];
        $this->attributesInfo[159] = [ 'PMIP6-Home-DHCP6-Server-Address', 'ipv6addr' ];
        $this->attributesInfo[160] = [ 'PMIP6-Visited-DHCP6-Server-Address', 'ipv6addr' ];
        $this->attributesInfo[161] = [ 'PMIP6-Home-IPv4-Gateway', 'ipv4addr' ];
        $this->attributesInfo[162] = [ 'PMIP6-Visited-IPv4-Gateway', 'ipv4addr' ];

        // RFC 6677
        $this->attributesInfo[163] = [ 'EAP-Lower-Layer', 'enum' ];

        // RFC 7055
        $this->attributesInfo[164] = [ 'GSS-Acceptor-Service-Name', 'text' ];
        $this->attributesInfo[165] = [ 'GSS-Acceptor-Host-Name', 'text' ];
        $this->attributesInfo[166] = [ 'GSS-Acceptor-Service-Specifics', 'text' ];
        $this->attributesInfo[167] = [ 'GSS-Acceptor-Realm-Name', 'text' ];

        // RFC 6911
        $this->attributesInfo[168] = [ 'Framed-IPv6-Address', 'ipv6addr' ];
        $this->attributesInfo[169] = [ 'DNS-Server-IPv6-Address', 'ipv6addr' ];
        $this->attributesInfo[170] = [ 'Route-IPv6-Information', 'ipv6prefix' ];
        $this->attributesInfo[171] = [ 'Delegated-IPv6-Prefix-Pool', 'text' ];
        $this->attributesInfo[172] = [ 'Stateful-IPv6-Address-Pool', 'text' ];

        // RFC 7268
        $this->attributesInfo[174] = [ 'Allowed-Called-Station-Id', 'text' ];
        $this->attributesInfo[175] = [ 'EAP-Peer-Id', 'S' ];
        $this->attributesInfo[176] = [ 'EAP-Server-Id', 'S' ];
        $this->attributesInfo[177] = [ 'Mobility-Domain-Id', 'I' ];
        $this->attributesInfo[178] = [ 'Preauth-Timeout', 'I' ];
        $this->attributesInfo[179] = [ 'Network-Id-Name', 'S' ];
        $this->attributesInfo[180] = [ 'EAPoL-Announcement', 'concat' ];
        $this->attributesInfo[181] = [ 'WLAN-HESSID', 'text' ];
        $this->attributesInfo[182] = [ 'WLAN-Venue-Info', 'I' ];
        $this->attributesInfo[183] = [ 'WLAN-Venue-Language', 'S' ];
        $this->attributesInfo[184] = [ 'WLAN-Venue-Name', 'text' ];
        $this->attributesInfo[185] = [ 'WLAN-Reason-Code', 'I' ];
        $this->attributesInfo[186] = [ 'WLAN-Pairwise-Cipher', 'I' ];
        $this->attributesInfo[187] = [ 'WLAN-Group-Cipher', 'I' ];
        $this->attributesInfo[188] = [ 'WLAN-AKM-Suite', 'I' ];
        $this->attributesInfo[189] = [ 'WLAN-Group-Mgmt-Cipher', 'I' ];
        $this->attributesInfo[190] = [ 'WLAN-RF-Band', 'I' ];
    }

    private function initAttributesNamesMap()
    {
        foreach($this->attributesInfo as $value => $attributeInfo) {
            $this->attributesNamesMap[strtolower($attributeInfo[0])] = $value;
        }
    }

    /**
     * Returns a string of the last error message and code, if any.
     *
     * @return string The last error message and code, or an empty string if no error set.
     */
    public function getLastError()
    {
        if (0 < $this->errorCode) {
            return $this->errorMessage.' ('.$this->errorCode.')';
        } else {
            return '';
        }
    }

    /**
     * Get the code of the last error.
     *
     * @return int  The error code
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }

    /**
     * Get the message of the last error.
     *
     * @return string  The last error message
     */
    public function getErrorMessage()
    {
        return $this->errorMessage;
    }

    /**
     * Enable or disable debug (console) output.
     *
     * @param bool $enabled  boolean true to enable debugging, anything else to disable it.
     *
     * @return self
     */
    public function setDebug($enabled = true)
    {
        $this->debug = (true === $enabled);
        return $this;
    }

    /**
     * Set the hostname or IP address of the RADIUS server to send requests to. If a hostname is supplied, the IP address
     * and protocol stack used are dependent on your system and DNS resolver.
     *
     * @param string $hostOrIp  The hostname or IP (v4 or v6) address of the RADIUS server to use
     * @return self
     *
     * @see self::accessRequestList() For a method that will try multiple IP addresses and/or hostnames
     */
    public function setServer($hostOrIp)
    {
        if (filter_var($hostOrIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            // IPv6 addresses must be enclosed with []'s in fsockopen
            $this->server = '[' . $hostOrIp . ']';
        } else {
            // Set the IP address or hostname of the RADIUS server
            $this->server = $hostOrIp;
        }
        return $this;
    }

    /**
     * Set the RADIUS shared secret between the client and RADIUS server.
     *
     * @param string $secret  The shared secret
     * @return self
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * Gets the currently set RADIUS shared secret.
     *
     * @return string  The shared secret
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the username suffix for authentication (e.g. '.ppp').
     * This must be set before setting the username.
     *
     * @param string $suffix  The RADIUS user suffix (e.g. .ppp)
     * @return self
     */
    public function setRadiusSuffix($suffix)
    {
        $this->suffix = $suffix;
        return $this;
    }

    /**
     * Set the username to authenticate as with the RADIUS server.
     * If the username does not contain the '@' character, then the RADIUS suffix
     * will be appended to the username.
     *
     * @param string $username  The username for authentication
     * @return self
     */
    public function setUsername($username = '')
    {
        if (false === strpos($username, '@') && !empty($this->suffix)) {
            $username .= $this->suffix;
        }

        $this->username = $username;
        $this->setAttribute(1, $this->username);

        return $this;
    }

    /**
     * Get the authentication username for RADIUS requests.
     *
     * @return string  The username for authentication
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Set the User-Password for PAP authentication.
     * Do not use this if you will be using CHAP-MD5, MS-CHAP v1, or MS-CHAP v2 passwords.
     *
     * @param string $password  The plain text password for authentication
     * @return self
     */
    public function setPassword($password)
    {
        $this->password    = $password;
        $encryptedPassword = $this->getEncryptedPassword($password, $this->getSecret(), $this->getRequestAuthenticator());

        $this->setAttribute(2, $encryptedPassword);

        return $this;
    }

    /**
     * Get the plaintext password for authentication.
     *
     * @return string  The authentication password
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Get a RADIUS encrypted password from a plaintext password, shared secret, and request authenticator.
     * This method should generally not need to be called directly.
     *
     * @param string $password The plain text password
     * @param string $secret   The RADIUS shared secret
     * @param string $requestAuthenticator  16 byte request authenticator
     * @return string  The encrypted password
     */
    public function getEncryptedPassword($password, $secret, $requestAuthenticator)
    {
        $encryptedPassword = '';
        $paddedPassword    = $password;

        if (0 != (strlen($password) % 16)) {
            $paddedPassword .= str_repeat(chr(0), (16 - strlen($password) % 16));
        }

        $previous = $requestAuthenticator;

        for ($i = 0; $i < (strlen($paddedPassword) / 16); ++$i) {
            $temp = md5($secret . $previous);

            $previous = '';
            for ($j = 0; $j <= 15; ++$j) {
                $value1 = ord(substr($paddedPassword, ($i * 16) + $j, 1));
                $value2 = hexdec(substr($temp, 2 * $j, 2));
                $xor_result = $value1 ^ $value2;
                $previous .= chr($xor_result);
            }
            $encryptedPassword .= $previous;
        }

        return $encryptedPassword;
    }

    /**
     * Set whether a Message-Authenticator attribute (80) should be included in the request.
     * Note: Some servers (e.g. Microsoft NPS) may be configured to require all packets contain this.
     *
     * @param bool $include  Boolean true to include in packets, false otherwise
     * @return self
     */
    public function setIncludeMessageAuthenticator($include = true)
    {
        if ($include) {
            $this->setAttribute(80, str_repeat("\x00", 16));
        } else {
            $this->removeAttribute(80);
        }

        return $this;
    }

    /**
     * Sets the next sequence number that will be used when sending packets.
     * There is generally no need to call this method directly.
     *
     * @param int $nextId  The CHAP packet identifier number
     * @return self
     */
    public function setChapId($nextId)
    {
        $this->chapIdentifier = (int)$nextId;

        return $this;
    }

    /**
     * Get the CHAP ID and increment the counter.
     *
     * @return int  The CHAP identifier for the next packet
     */
    public function getChapId()
    {
        $id = $this->chapIdentifier;
        $this->chapIdentifier++;

        return $id;
    }

    /**
     * Set the CHAP password (for CHAP authentication).
     *
     * @param string $password  The plaintext password to hash using CHAP.
     * @return self
     */
    public function setChapPassword($password)
    {
        $chapId = $this->getChapId();
        $chapMd5 = $this->getChapPassword($password, $chapId, $this->getRequestAuthenticator());

        $this->setAttribute(3, pack('C', $chapId) . $chapMd5);

        return $this;
    }

    /**
     * Generate a CHAP password.  There is generally no need to call this method directly.
     *
     * @param string $password  The password to hash using CHAP
     * @param int    $chapId    The CHAP packet ID
     * @param string $requestAuthenticator  The request authenticator value
     * @return string The hashed CHAP password
     */
    public function getChapPassword($password, $chapId, $requestAuthenticator)
    {
        return md5(pack('C', $chapId) . $password . $requestAuthenticator, true);
    }

    /**
     * Set the MS-CHAP password in the RADIUS packet (for authentication using MS-CHAP passwords)
     *
     * @param string  $password  The plaintext password
     * @param string  $challenge The CHAP challenge
     * @return self
     */
    public function setMsChapPassword($password, $challenge = null)
    {
        $chap = new \Crypt_CHAP_MSv1();
        $chap->chapid   = mt_rand(1, 255);
        $chap->password = $password;
        if (is_null($challenge)) {
            $chap->generateChallenge();
        } else {
            $chap->challenge = $challenge;
        }

        $response = pack('C', $chap->chapid) // Ident
            . "\x01"                         // Flags
            . str_repeat("\0", 24)           // LM-Response
            . $chap->ntChallengeResponse();  // NT-Response

        $this->setIncludeMessageAuthenticator();
        $this->setVendorSpecificAttribute(VendorId::MICROSOFT, 11, $chap->challenge);
        $this->setVendorSpecificAttribute(VendorId::MICROSOFT, 1, $response);

        return $this;
    }

    /**
     * Sets the MS-CHAPv2 password for authentication by generating the MS-CHAP2 Response.
     *
     * @param string $username The username for authentication
     * @param string $password The password associated with the username
     * @since 3.1.0
     * @return self
     */
    public function setMsChapV2Password($username, $password)
    {
        /*
         * Notes:
         * - MS-CHAP-Challenge (VSA 11) MUST be 16 bytes: the Authenticator Challenge.
         * - MS-CHAP2-Response (VSA 25) MUST be 50 bytes structured as:
         *     1 byte Ident, 1 byte Flags (0), 16 bytes Peer-Challenge,
         *     8 bytes reserved (zeros), 24 bytes NT-Response.
         * - The NT-Response depends on Username, Peer-Challenge, and Authenticator-Challenge.
         */

        $chap = new \Crypt_CHAP_MSv2;
        $chap->chapid   = mt_rand(1, 255);
        $chap->username = $username;
        $chap->password = $password;

        // Build the NT-Response (24 bytes) using username, peerChallenge, and authChallenge
        $ntResponse = $chap->challengeResponse();

        // Build the 50-byte MS-CHAP2-Response attribute value per RFC 2548 Section 2.3.3
        $mschap2Response =
            chr($chap->chapid) .        // Ident
            chr(0x00) .                 // Flags (0)
            $chap->peerChallenge .      // 16 bytes
            str_repeat("\x00", 8) .     // 8 bytes reserved
            $ntResponse;                // 24 bytes NT-Response

        // MS-CHAP-Challenge (type 11) must be the 16-byte Authenticator Challenge
        $this->setVendorSpecificAttribute(VendorId::MICROSOFT, 11, $chap->authChallenge);

        // MS-CHAP2-Response (type 25) is the 50-byte structure built above
        $this->setVendorSpecificAttribute(VendorId::MICROSOFT, 25, $mschap2Response);

        return $this;
    }

    /**
     * Sets the Network Access Server (NAS) IP address (the RADIUS client IP).
     *
     * @param string $hostOrIp  The hostname or IP address of the RADIUS client
     * @return self
     */
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

    /**
     * Get the currently set NAS IP address
     *
     * @return string  The NAS hostname or IP
     */
    public function getNasIPAddress()
    {
        return $this->nasIpAddress;
    }

    /**
     * Set the physical port number of the NAS which is authenticating the user.
     *
     * @param int $port  The NAS port
     * @return self
     */
    public function setNasPort($port = 0)
    {
        $this->nasPort = intval($port);
        $this->setAttribute(5, $this->nasPort);

        return $this;
    }

    /**
     * Get the NAS port attribute
     *
     * @return string
     */
    public function getNasPort()
    {
        return $this->nasPort;
    }

    /**
     * Set the timeout (in seconds) after which we'll give up waiting for a response from the RADIUS server.
     *
     * @param int $timeout  The timeout (in seconds) for waiting for RADIUS responses.
     * @return self
     */
    public function setTimeout($timeout = 5)
    {
        if (intval($timeout) > 0) {
            $this->timeout = intval($timeout);
        }

        return $this;
    }

    /**
     * Get the current timeout value for RADIUS response packets.
     *
     * @return int  The timeout
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * Set the port number used by the RADIUS server for authentication (default = 1812).
     *
     * @param int $port  The port for sending Access-Request packets
     * @return self
     */
    public function setAuthenticationPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536)) {
            $this->authenticationPort = intval($port);
        }

        return $this;
    }

    /**
     * Get the port number used for authentication
     *
     * @return int  The RADIUS auth port
     */
    public function getAuthenticationPort()
    {
        return $this->authenticationPort;
    }

    /**
     * Set the port number used by the RADIUS server for accounting (default = 1813)
     *
     * @param int $port  The port for sending Accounting request packets
     * @return self
     */
    public function setAccountingPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536))
        {
            $this->accountingPort = intval($port);
        }

        return $this;
    }

    /**
     * Get the RFC 5176 Dynamic Authorization port used for CoA and Disconnect requests
     *
     * @return int  The RFC 5176 Dynamic Authorization port
     */
    public function getDynamicAuthorizationPort()
    {
        return $this->dynamicAuthorizationPort;
    }

    /**
     * Set the port number used for RFC 5176 Dynamic Authorizations (default = 3799)
     *
     * @param int $port  The port for sending CoA and disconnect request packets
     * @return self
     */
    public function setDynamicAuthorizationPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536))
        {
            $this->dynamicAuthorizationPort = intval($port);
        }

        return $this;
    }

    /**
     * Returns the raw wire data of the last received RADIUS packet.
     *
     * @return string  The raw packet data of the last RADIUS response
     */
    public function getResponsePacket()
    {
        return $this->radiusPacketReceived;
    }

    /**
     * Alias of Radius::getAttribute()
     *
     * @param int|string $type  The attribute ID or name to get
     * @return NULL|string NULL if no such attribute was set in the response packet, or the data of that attribute
     */
    public function getReceivedAttribute($type)
    {
        return $this->getAttribute($type);
    }

    /**
     * Returns an array of all attributes from the last received RADIUS packet.
     *
     * @return array  Array of received attributes.  Each entry is an array with $attr[0] = attribute ID, $attr[1] = data
     */
    public function getReceivedAttributes()
    {
        return $this->attributesReceived;
    }

    /**
     * For debugging purposes.  Print the attributes from the last received packet as a readable string
     *
     * @return string  The RADIUS packet attributes in human readable format
     */
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
                    $attributes = $receivedAttr[1];
                }

                $attributes .= "<br>\n";
            }
        }

        return $attributes;
    }

    /**
     * Get the value of an attribute from the last received RADIUS response packet.
     *
     * @param int|string $type    The attribute ID or name to get
     * @return NULL|string NULL if no such attribute was set in the response packet, or the data of that attribute
     */
    public function getAttribute($type)
    {
        $value = null;

        if (is_string($type) && !preg_match('/^\d+(?:\.\d+)?$/', $type)) {
            $type = $this->getAttributeTypeValueByName($type);
            if (!$type) {
                throw new \InvalidArgumentException("Attribute '$type' is not mapped to a RADIUS attribute type");
            }
        }

        if (is_array($this->attributesReceived)) {
            foreach($this->attributesReceived as $attr) {
                if (intval($type) == $attr[0]) {
                    $value = $attr[1];
                    break;
                }
            }
        }

        return $value;
    }

    /**
     * Gets the name of a RADIUS packet from the numeric value.
     * This is only used for debugging functions
     *
     * @param int $info_index  The packet type number
     * @return mixed|string
     */
    public function getRadiusPacketInfo($info_index)
    {
        if (isset($this->radiusPackets[intval($info_index)])) {
            return $this->radiusPackets[intval($info_index)];
        } else {
            return '';
        }
    }

    /**
     * Gets the info about a RADIUS attribute identifier such as the attribute name and data type.
     * This is used internally for encoding packets and debug output.
     *
     * @param int $info_index  The RADIUS packet attribute number
     * @return array 2 element array with Attribute-Name and Data Type
     */
    public function getAttributesInfo($info_index)
    {
        if (isset($this->attributesInfo[intval($info_index)])) {
            return $this->attributesInfo[intval($info_index)];
        } else {
            return array('', '');
        }
    }

    /**
     * Get a RADIUS attribute value by its name.
     *
     * @see self::initDefaultAttributes()
     * @param $name The name of the attribute to get (e.g. User-Name, NAS-IP-Address)
     * @return int 0 if the attribute name is unknown, otherwise, the attribute name's value
     */
    public function getAttributeTypeValueByName($name)
    {
        if (empty($this->attributesNamesMap)) {
            $this->initAttributesNamesMap();
        }

        $name = strtolower($name);

        if (isset($this->attributesNamesMap[$name])) {
            return $this->attributesNamesMap[$name];
        } else {
            return 0;
        }
    }

    /**
     * Set an arbitrary RADIUS attribute to be sent in the next packet.
     *
     * @param string $type  The attribute type value as a number or in "dotten number" notation
     * @param mixed  $value  The value of the attribute
     * @return self
     */
    public function setAttribute($type, $value)
    {
        if (is_string($type) && !preg_match('/^\d+(?:\.\d+)?$/', $type)) {
            $type = $this->getAttributeTypeValueByName($type);
            if (!$type) {
                throw new \InvalidArgumentException("Attribute '$type' is not mapped to a RADIUS attribute type");
            }
        }

        $index = -1;
        if (is_array($this->attributesToSend)) {
            foreach($this->attributesToSend as $i => $attr) {
                if (is_array($attr)) {
                    $tmp = $attr[0];
                } else {
                    $tmp = $attr;
                }
                if ($type == ord(substr($tmp, 0, 1))) {
                    $index = $i;
                    break;
                }
            }
        }

        $temp = null;

        if (isset($this->attributesInfo[$type])) {
            $temp = $this->encodeRadiusAttribute($type, $value, $this->attributesInfo[$type][1]);
        }

        // concat & vsa types
        $multiAVP = isset($this->attributesInfo[$type]) && in_array($this->attributesInfo[$type][1], [ 6, 14, self::DATA_TYPE_CONCAT, self::DATA_TYPE_VSA ]);

        if ($index > -1) {
            if ($multiAVP) {
                $this->attributesToSend[$index][] = $temp;
                $action = 'Added';
            } else {
                $this->attributesToSend[$index] = $temp;
                $action = 'Modified';
            }
        } else {
            $this->attributesToSend[] = $multiAVP ? [ $temp ] : $temp;
            $action = 'Added';
        }

        $info = $this->getAttributesInfo($type);
        // Match for most non-printable chars somewhat taking multibyte chars into account
        if (preg_match('/[^\x09-\x0d\x1b\x20-\xff]/', $value) === 1) {
            $value = '0x' . bin2hex($value);
        }
        $this->debugInfo("{$action} Attribute {$type} ({$info[0]}), format {$info[1]}, value <em>{$value}</em>");

        return $this;
    }

    /**
     * Encodes a RADIUS attribute based on its type, value, and data type specification.
     *
     * @since 3.1.0
     * @param int $type The attribute type identifier.
     * @param mixed $value The value to be encoded according to the given data type.
     * @param int|string $dataType The specified data type for encoding the value.
     * @return string The encoded RADIUS attribute as a binary string.
     * @throws InvalidArgumentException If the provided value or format is invalid for certain data types.
     * @throws Exception If unsupported or unknown attribute types are encountered.
     */
    public function encodeRadiusAttribute($type, $value, $dataType)
    {
        $temp = null;

        if (array_key_exists($dataType, $this->dataTypeMap)) {
            $newDataType = $this->dataTypeMap[$dataType];
            $dataType = $newDataType;
        }

        switch ($dataType) {
            // integer
            case 1:
            case $this->radiusDataTypes[1]:
            // and enum
            case 2:
            case $this->radiusDataTypes[2]:
                // Integer, 32 bit unsigned value, most significant octet first.
                $temp = chr($type) . chr(6) .
                    chr(intval(($value / (256 * 256 * 256))) % 256) .
                    chr(intval(($value / (256 * 256))) % 256) .
                    chr(intval(($value / (256))) % 256) .
                    chr($value % 256);
                break;

            // time
            case 3:
            case $this->radiusDataTypes[3]:
                /*
                 * The "time" data type encodes time as a 32-bit unsigned value in
                 * network byte order and in seconds since 00:00:00 UTC, January 1,
                 * 1970.  We note that dates before the year 2017 are likely to indicate
                 * configuration errors or lack of access to the correct time.
                 *
                 * Note that the "time" attribute is defined to be unsigned, which means
                 * that it is not subject to a signed integer overflow in the year 2038.
                 */
                $temp = chr($type) . chr(6) . pack('N', $value);
                break;

            // text
            case $this->radiusDataTypes[4]:
            case 4:
                // Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                $temp = chr($type) . chr(2 + strlen($value)) . $value;
                break;

            // string
            case 5:
            case $this->radiusDataTypes[5]:
                // String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
                $temp = chr($type) . chr(2 + strlen($value)) . $value;
                break;

            // concat
            case 6:
            case $this->radiusDataTypes[6]:
                $temp = '';
                while(strlen($value)) {
                    $v = substr($value, 0, 253);
                    $temp .= chr($type) . chr(2 + strlen($v)) . $v;
                    $value = substr($value, 253);
                }
                break;

            // ipv4addr
            case 8:
            case $this->radiusDataTypes[8]:
                // Address, 32-bit value, most significant octet first.
                $ip = explode('.', $value);
                $temp = chr($type) . chr(6) . chr($ip[0]) . chr($ip[1]) . chr($ip[2]) . chr($ip[3]);
                break;

            // ipv6addr
            case 9:
            case $this->radiusDataTypes[9]:
                $temp = chr($type) . chr(18) . inet_pton($value);
                break;

            // ipv6prefix
            case 10:
            case $this->radiusDataTypes[10]:
                if (strpos($value, '/') === false) {
                    throw new InvalidArgumentException("IPv6 prefix length missing");
                }
                [ $addr, $prefixLen ] = explode('/', $value, 2);
                $prefixLen = (int)$prefixLen;

                $addr = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
                if ($addr === false) {
                    throw new \InvalidArgumentException("IPv6 address prefix is invalid");
                }

                if ($prefixLen < 0 || $prefixLen > 128) {
                    throw new InvalidArgumentException("IPv6 prefix length must be 0..128");
                }

                $addr = inet_pton($addr);
                if ($addr === false || strlen($addr) !== 16) {
                    throw new InvalidArgumentException("Invalid IPv6 address");
                }

                // Determine the number of full octets needed to cover the prefix length.
                $octets = (int)ceil($prefixLen / 8);

                if ($octets > 0) {
                    // The Prefix field SHOULD NOT contain more octets than necessary to encode the Prefix field.
                    $prefix = substr($addr, 0, $octets);

                    $excessBits = ($octets * 8) - $prefixLen;
                    if ($excessBits > 0) {
                        // Zero the least-significant excess bits in the last octet.
                        $last = ord($prefix[$octets - 1]);
                        $last &= 0xFF << $excessBits;
                        $prefix[$octets - 1] = chr($last);
                    }
                } else {
                    // Prefix length 0, no address octets.
                    $prefix = '';
                }

                $reserved = 0;
                $temp = chr($type) . chr(2 + 1 + 1 + strlen($prefix)) . chr($reserved) . chr($prefixLen) . $prefix;
                break;

            // ipv4prefix
            case 11:
            case $this->radiusDataTypes[11]:
                if (!preg_match('|^\d+\.\d+\.\d+\.\d+/\d{1,2}$|', $value)) {
                    throw new \InvalidArgumentException("Invalid IPv4 prefix format");
                }

                [ $addr, $prefixLen ] = explode('/', $value, 2);
                $prefixLen = (int)$prefixLen;

                $addr = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
                if ($addr === false) {
                    throw new \InvalidArgumentException("Invalid IPv4 address prefix");
                }

                if ((int)$prefixLen < 0 || (int)$prefixLen > 32) {
                    throw new \InvalidArgumentException("IPv4 prefix length must be 0..32");
                }

                $addr = ip2long($addr);
                if ($addr === false) {
                    throw new \InvalidArgumentException("Invalid IPv4 address prefix");
                }

                if ($addr === 0) {
                    $prefix = 32;
                }

                $mask = $prefixLen == 32 ? 0 : (~0 << (32 - $prefixLen)) & 0xffffffff;

                $prefix = $addr & $mask;
                $prefix = pack('N', $prefix);  // 4 octets, fixed

                $reserved = 0;

                $temp = chr($type) . chr(2 + 2 + 4) . chr($reserved) . chr($prefixLen) . $prefix;
                break;

            // ifid
            case 7:
            case $this->radiusDataTypes[7]:
            // integer64
            case 12:
            case $this->radiusDataTypes[12]:
                $temp = chr($type) . chr(10) . pack('J', $value); // unsigned 64 bit network byte order
                break;

            // tlv
            case 13:
            case $this->radiusDataTypes[13]:
                throw new \Exception('tlv attributes are not supported');

            // vsa
            case 14:
            case $this->radiusDataTypes[14]:
                $temp = chr($type) . chr(2 + strlen($value)) . $value;
                break;

            case 15:
            case $this->radiusDataTypes[15]:
                throw new \Exception("extended attributes are not supported");

            case 16:
            case $this->radiusDataTypes[16]:
                throw new \Exception("long-extended attributes are not supported");

            case 17:
            case $this->radiusDataTypes[17]:
                throw new \Exception("evs attributes are not supported");

            default:
                throw new \Exception("Unknown RADIUS attribute type $type");
        }

        return $temp;
    }

    /**
     * Get a single attribute or all attributes from the list of attributes to send.
     * When getting a single attribute, the decoded value is returned. When getting all attributes, an array of encoded
     * attributes are returned where each attribute includes the type, encoded length, and the value encoded according
     * to its type definition.
     *
     * @param int|null $type  RADIUS attribute type, or null to return all attributes.
     * @return mixed|null array of encoded attributes, a decoded attribute value depending on the type, or null if the
     * attribute was not found
     */
    public function getAttributesToSend($type = null, $index = 0)
    {
        if (!is_array($this->attributesToSend)) {
            return [];
        } elseif (is_null($type)) {
            return $this->attributesToSend; // return all attributes
        }

        foreach($this->attributesToSend as $i => $attr) {
            if (is_array($attr)) {
                $attrType = ord(substr($attr[0], 0, 1));
            } else {
                $attrType = ord(substr($attr, 0, 1));
            }

            if ($type != $attrType) {
                continue;
            }

            if (is_array($attr) && !isset($attr[$index])) {
                return null;
            } elseif (is_array($attr) && $index === -1) {
                return $attr; // return all attributes from this type
            } elseif (is_array($attr)) {
                $attrValue = $attr[$index];
            } else {
                $attrValue = $attr;
            }

            $attrValue = substr($attrValue, 2);

            return $this->decodeRadiusAttribute($attrValue, $type);
        }

        return null;
    }

    /**
     * Adds a vendor-specific attribute to the RADIUS packet
     *
     * @param int    $vendorId  The RADIUS vendor ID
     * @param int    $attributeType  The attribute number of the vendor-specific attribute
     * @param mixed  $attributeValue The data for the attribute
     * @param string $dataType The data type of the attribute (default: string)
     * @return self
     */
    public function setVendorSpecificAttribute($vendorId, $attributeType, $attributeValue, $dataType = self::DATA_TYPE_STRING)
    {
        $vsa = $this->encodeRadiusAttribute($attributeType, $attributeValue, $dataType);
        $this->setAttribute(26, pack('N', $vendorId) . $vsa);

        return $this;
    }

    /**
     * Remove an attribute from a RADIUS packet
     *
     * @param int    $type  The attribute number to remove
     * @return self
     */
    public function removeAttribute($type)
    {
        if (is_array($this->attributesToSend)) {
            foreach($this->attributesToSend as $i => $attr) {
                if (is_array($attr)) {
                    $tmp = $attr[0];
                } else {
                    $tmp = $attr;
                }
                if ($type == ord(substr($tmp, 0, 1))) {
                    unset($this->attributesToSend[$i]);
                    break;
                }
            }
        }

        return $this;
    }

    /**
     * Clear all attributes to send so the next packet contains no attributes except ones added after calling this function.
     *
     * @return self
     */
    public function resetAttributes()
    {
        $this->attributesToSend = [];
        return $this;
    }

    /**
     * Add a RADIUS attribute type to the list of supported attributes
     *
     * @since 3.1.0
     * @param int $type The attribute type (number) to add
     * @param $description The attribute description
     * @param $dataType The data type of the attribute
     * @return $this
     *
     */
    public function addRadiusAttribute($type, $description, $dataType)
    {
        if ($type < 1 || $type > 255) {
            throw new \InvalidArgumentException("Attribute type must be in range 1-255");
        }

        if (array_key_exists($dataType, $this->dataTypeMap)) {
            $dataType = $this->dataTypeMap[$dataType];
        } elseif (!array_key_exists($dataType, $this->radiusDataTypes) && !in_array($dataType, $this->radiusDataTypes)) {
            throw new \InvalidArgumentException("Unsupported attribute data type '$dataType'");
        }

        $this->attributesInfo[$type] = [ $description, $dataType ];
        $this->attributesNamesMap[strtolower($description)] = $type;

        return $this;
    }

    /**
     * Remove vendor specific attributes from the request.
     *
     * @return self
     */
    public function resetVendorSpecificAttributes()
    {
        $this->removeAttribute(26);

        return $this;
    }

    /**
     * Decodes a vendor specific attribute in a response packet
     *
     * @param string $rawValue  The raw packet attribute data as seen on the wire
     * @return array  Array of vendor specific attributes in the response packet
     */
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

    /**
     * Issue an Access-Request packet to the RADIUS server.
     *
     * @param string $username  Username to authenticate as
     * @param string $password  Password to authenticate with using PAP
     * @param int    $timeout   The timeout (in seconds) to wait for a response packet
     * @param string $state     The state of the request (default is Service-Type=1)
     * @return boolean          true if the server sent an Access-Accept packet, false otherwise
     */
    public function accessRequest($username = '', $password = '', $timeout = 0, $state = null)
    {
        $this->clearDataReceived()
             ->clearError()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);

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

        $packetData = $this->generateRadiusPacket();

        $conn = $this->sendRadiusRequest($packetData);
        if (!$conn) {
            $this->debugInfo(sprintf(
                'Failed to send packet to %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        $receivedPacket = $this->readRadiusResponse($conn);
        @fclose($conn);

        if (!$receivedPacket) {
            $this->debugInfo(sprintf(
                'Error receiving response packet from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if (!$this->parseRadiusResponsePacket($receivedPacket)) {
            $this->debugInfo(sprintf(
                'Bad RADIUS response from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if ($this->radiusPacketReceived == self::TYPE_ACCESS_REJECT) {
            $this->errorCode    = 3;
            $this->errorMessage = 'Access rejected';
        }

        return (self::TYPE_ACCESS_ACCEPT == ($this->radiusPacketReceived));
    }

    /**
     * Perform an accessRequest against a list of servers.  Each server must
     * share the same RADIUS secret.  This is useful if you have more than one
     * RADIUS server.  This function tries each server until it receives an
     * Access-Accept or Access-Reject response.  That is, it will try more than
     * one server in the event of a timeout or other failure.
     *
     * @see \Dapphp\Radius\Radius::accessRequest()
     *
     * @param array  $serverList  Array of servers to authenticate against
     * @param string $username    Username to authenticate as
     * @param string $password    Password to authenticate with using PAP
     * @param int    $timeout     The timeout (in seconds) to wait for a response packet
     * @param string $state       The state of the request (default is Service-Type=1)
     *
     * @return boolean true if the server sent an Access-Accept packet, false otherwise
     */
    public function accessRequestList($serverList, $username = '', $password = '', $timeout = 0, $state = null)
    {
        $result = false;

        if (!is_array($serverList)) {
            $this->errorCode    = 127;
            $this->errorMessage = sprintf(
                'server list passed to accessRequestList must be array; %s given', gettype($serverList)
            );

            return false;
        } elseif (empty($serverList)) {
            $this->errorCode    = 128;
            $this->errorMessage = 'server list passed to accessRequestList was empty';
        }

        $attributes = $this->getAttributesToSend(); // store base attributes

        foreach($serverList as $server) {
            $this->setServer($server);

            $result = $this->accessRequest($username, $password, $timeout, $state);

            if ($result === true) {
                break; // success
            } elseif ($this->getErrorCode() === self::TYPE_ACCESS_REJECT) {
                break; // access rejected
            } else {
                /* timeout or other possible transient error; try next host */
                $this->attributesToSend = $attributes; // reset base attributes
                $this->generateRequestAuthenticator(); // generate a new random request authenticator
            }
        }

        return $result;
    }

    /**
     * Authenticate using EAP-MS-CHAP v2.  This is a 4-way authentication
     * process that sends an Access-Request, receives an Access-Challenge,
     * responds with an Access-Request, and finally sends an Access-Request with
     * an EAP success packet if the last Access-Challenge was a success.
     *
     * Windows Server NPS: EAP Type: MS-CHAP v2
     *
     * @param string $username  The username to authenticate as
     * @param string $password  The plain text password that will be hashed using MS-CHAPv2
     * @return boolean          true if negotiation resulted in an Access-Accept packet, false otherwise
     */
    public function accessRequestEapMsChapV2($username, $password)
    {
        /*
         * RADIUS EAP MS-CHAP-V2 Process:
         * > RADIUS ACCESS_REQUEST w/ EAP identity packet
         * < ACCESS_CHALLENGE w/ MS-CHAP challenge encapsulated in EAP request
         *   CHAP packet contains auth_challenge value
         *   Calculate encrypted password based on challenge for response
         * > ACCESS_REQUEST w/ MS-CHAP challenge response, peer_challenge &
         *   encrypted password encapsulated in an EAP response packet
         * < ACCESS_CHALLENGE w/ MS-CHAP success or failure in EAP packet.
         * > ACCESS_REQUEST w/ EAP success packet if challenge was accepted
         *
         */

        $attributes = $this->getAttributesToSend();


        // compose and send identity packet as a start of authentication
        $eapPacket = EAPPacket::identity($username);

        $this->clearDataToSend()
             ->clearError()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);

        $this->attributesToSend = $attributes;
        $this->setUsername($username)
             ->removeAttribute(79)
             ->setAttribute(79, $eapPacket)
             ->setIncludeMessageAuthenticator();

        $this->accessRequest();

        if ($this->errorCode) {
            return false;
        }

        if ($this->radiusPacketReceived != self::TYPE_ACCESS_CHALLENGE) {
            $this->errorCode    = 102;
            $this->errorMessage = 'Access-Request did not get Access-Challenge response';
            return false;
        }

        $state = $this->getReceivedAttribute(24);
        $eap   = $this->getReceivedAttribute(79);

        if ($eap == null) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP packet missing from Radius access challenge packet';
            return false;
        }

        $eap = EAPPacket::fromString($eap);

        // checking what type of EAP-Message we have
        // if it is a PEAP proposal, we start an EAP fallback
        if ($eap->type == EAPPacket::TYPE_PEAP_EAP) { // fallback if PEAP
            $eapId     = $eap->id;

            $eapPacket = EAPPacket::legacyNak(EAPPacket::TYPE_EAP_MS_AUTH, $eapId);

            $this->clearDataToSend()
                 ->setPacketType(self::TYPE_ACCESS_REQUEST);

            $this->attributesToSend = $attributes;
            $this->setUsername($username)
                 ->setAttribute(79, $eapPacket)
                 ->setIncludeMessageAuthenticator();

            $resp = $this->accessRequest('', '', 0, $state);

            if (!$resp) {
                return false;
            }

            $eap = $this->getReceivedAttribute(79);

            if ($eap == null) {
                $this->errorCode    = 102;
                $this->errorMessage = 'EAP packet missing from Radius EAP fallback';
                return false;
            }

            $eap = EAPPacket::fromString($eap);
        } elseif ($eap->type == EAPPacket::TYPE_MD5_CHALLENGE) {
            // EAP type MD5, PPP CHAP protocol w/ MD5
            $this->removeAttribute(79)
                ->setChapPassword($password);

            return $this->accessRequest($username);
        }

        // since we have check that we are not in PEAP method, we should be in EAP
        // so let's check this and return error if not
        if ($eap->type != EAPPacket::TYPE_EAP_MS_AUTH) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP type is not EAP_MS_AUTH or MD5_CHALLENGE in access response';
            return false;
        }

        $chapPacket = MsChapV2Packet::fromString($eap->data);

        if (!$chapPacket || $chapPacket->opcode != MsChapV2Packet::OPCODE_CHALLENGE) {
            $this->errorCode    = 102;
            $this->errorMessage = 'MS-CHAP-V2 access response packet missing challenge';
            return false;
        }

        $challenge  = $chapPacket->challenge;
        $chapId     = $chapPacket->msChapId;

        $msChapV2   = new \Crypt_CHAP_MSv2;
        $msChapV2->username      = $username;
        $msChapV2->password      = $password;
        $msChapV2->chapid        = $chapId;
        $msChapV2->authChallenge = $challenge;

        $chapPacket->opcode    = MsChapV2Packet::OPCODE_RESPONSE;
        $chapPacket->response  = $msChapV2->challengeResponse();
        $chapPacket->name      = $username;
        $chapPacket->challenge = $msChapV2->peerChallenge;

        $eapPacket = EAPPacket::mschapv2($chapPacket, $chapId);

        $this->clearDataToSend()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);
        $this->attributesToSend = $attributes;
        $this->setUsername($username)
             ->setAttribute(79, $eapPacket)
             ->setIncludeMessageAuthenticator();

        $this->accessRequest('', '', 0, $state);

        if ($this->errorCode) {
            return false;
        }

        $eap = $this->getReceivedAttribute(79);

        if ($eap == null) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP packet missing from MS-CHAP-V2 challenge response';
            return false;
        }

        $eap = EAPPacket::fromString($eap);

        if ($eap->type != EAPPacket::TYPE_EAP_MS_AUTH) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP type is not EAP_MS_AUTH in access response';
            return false;
        }

        $chapPacket = MsChapV2Packet::fromString($eap->data);

        if ($chapPacket->opcode != MsChapV2Packet::OPCODE_SUCCESS) {
            $this->errorCode = 3;

            $err = (!empty($chapPacket->response)) ? $chapPacket->response : 'General authentication failure';

            $pattern = '/E=(\d{1,10}).*R=(\d).*C=([0-9A-Fa-f]{32}).*V=(\d{1,10})/';

            if (preg_match($pattern, $chapPacket->response, $err)) {
                switch($err[1]) {
                    case '691':
                        $err = 'Authentication failure, username or password incorrect.';
                        break;

                    case '646':
                        $err = 'Authentication failure, restricted logon hours.';
                        break;

                    case '647':
                        $err = 'Account disabled';
                        break;

                    case '648':
                        $err = 'Password expired';
                        break;

                    case '649':
                        $err = 'No dial in permission';
                        break;

                    case '709':
                        $err = 'Error changing password';
                        break;
                }
            }

            $this->errorMessage = $err;
            return false;
        }

        // got a success response - send success acknowledgement
        $eapPacket = EAPPacket::eapSuccess($chapId + 1);
        $state     = $this->getReceivedAttribute(24);

        $this->clearDataToSend()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);
        $this->attributesToSend = $attributes;
        $this->setUsername($username)
             ->setAttribute(79, $eapPacket)
             ->setIncludeMessageAuthenticator();

        return $this->accessRequest('', '', 0, $state);
    }

    /**
     * Allows the peer to change the password on the account specified in the preceding Response packet. The Change-Password
     * packet should be sent only if the authenticator reports ERROR_PASSWD_EXPIRED (E=648) in the Message field of the
     * Failure packet. RFC 2759 - 7. Change-Password Packet
     *
     * @param string $username The account username
     * @param string $password The expired password
     * @param string $newPassword The new password for the account
     * @return bool true if the password was changed, otherwise false and $this->errorCode and $this->errorMessage are set
     */
    public function changePasswordEapMsChapV2($username, $password, $newPassword)
    {
        $this->removeAttribute(79);
        $attributes = $this->getAttributesToSend();

        /*
        $resp may be:
            true in case of valid auth (not expired, not disabled, good pwd...)
            false with chap-opcode=failure and err=648
            false with other cases
        */
        $resp = $this->accessRequestEapMsChapV2($username, $password);

        if ($resp) {
            $this->errorCode = 3;
            $this->errorMessage = 'Password must be expired to be changed';
            return false;
        }

        if ($this->radiusPacketReceived == self::TYPE_ACCESS_REJECT) {
            $this->errorCode    = 3;
            $this->errorMessage = 'Access rejected, invalid account';
            return false;
        } elseif ($this->radiusPacketReceived != self::TYPE_ACCESS_CHALLENGE) {
            $this->errorCode    = 102;
            $this->errorMessage = 'Access-Request did not get Access-Challenge response';
            return false;
        }

        $state = $this->getReceivedAttribute(24);
        $eap   = $this->getReceivedAttribute(79);

        if ($eap == null) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP packet missing from Radius access challenge packet';
            return false;
        }

        $eap = EAPPacket::fromString($eap);

        if ($eap->type != EAPPacket::TYPE_EAP_MS_AUTH) {
            $this->errorCode    = 102;
            $this->errorMessage = 'EAP type is not EAP_MS_AUTH in access response';
            return false;
        }

        $chapPacket = MsChapV2Packet::fromString($eap->data);

        // chap response opcode should be OPCODE_FAILURE, other cases are exceptions
        if (!$chapPacket || $chapPacket->opcode != MsChapV2Packet::OPCODE_FAILURE) {
            $this->errorCode    = 102;
            $this->errorMessage = 'Invalid reply from auth server';
            return false;
        }

        $err      = (!empty($chapPacket->response)) ? $chapPacket->response : 'General authentication failure';
        $pattern  = '/E=(\d{1,10}).*R=(\d).*C=([0-9A-Fa-f]{32}).*V=(\d{1,10})/';
        $pm       = preg_match($pattern, $chapPacket->response, $err);

        if (!$pm) {
            $this->errorCode    = 102;
            $this->errorMessage = 'Invalid reply from auth server';
            return false;
        }

        if ($err[1] == '648') {
            $challenge = pack("H*", $err[3]);
        } else {
            switch($err[1]) {
                case '691':
                    $err = 'Authentication failure, username or password incorrect.';
                    break;

                case '646':
                    $err = 'Authentication failure, restricted logon hours.';
                    break;

                case '647':
                    $err = 'Account disabled';
                    break;

                case '649':
                    $err = 'No dial in permission';
                    break;

                case '709':
                    $err = 'Error changing password';
                    break;
            }

            $this->errorCode    = 3;
            $this->errorMessage = $err;
            return false;
        }

        $chapId     = $chapPacket->msChapId + 1;

        $msChapV2   = new \Crypt_CHAP_MSv2;
        $msChapV2->username      = $username;
        $msChapV2->password      = $password;
        $msChapV2->chapid        = $chapId;
        $msChapV2->authChallenge = $challenge;

        $chapPacket->opcode        = MsChapV2Packet::OPCODE_CHANGEPASS;
        $chapPacket->msChapId      = $chapId;
        $chapPacket->name          = $username;
        $chapPacket->response      = $msChapV2->challengeResponse();
        $chapPacket->challenge     = $msChapV2->peerChallenge;
        $chapPacket->encryptedPwd  = $msChapV2->newPasswordEncryptedWithOldNtPasswordHash($newPassword, $password);
        $chapPacket->encryptedHash = $msChapV2->oldNtPasswordHashEncryptedWithNewNtPasswordHash($newPassword, $password);

        $eapPacketSplit = str_split(EAPPacket::mschapv2($chapPacket, $chapId), 253);

        $this->clearDataToSend()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);
        $this->attributesToSend = $attributes;
        $this->setUsername($username)
             ->setAttribute(79, $eapPacketSplit[0])
             ->setAttribute(79, $eapPacketSplit[1])
             ->setAttribute(79, $eapPacketSplit[2])
             ->setIncludeMessageAuthenticator();

        $resp = $this->accessRequest('', '', 0, $state);

        if ($this->errorCode) {
            $this->errorMessage = 'Password change rejected; new password may not meet the password policy requirements';
            return false;
        }

        // got a success response - send success acknowledgement
        $eapPacket = EAPPacket::eapSuccess($chapId + 1);

        $this->clearDataToSend()
             ->setPacketType(self::TYPE_ACCESS_REQUEST);
        $this->attributesToSend = $attributes;
        $this->setUsername($username)
             ->setAttribute(79, $eapPacket)
             ->setIncludeMessageAuthenticator();

        // returns true if password changed successfully
        return $this->accessRequest('', '', 0, $state);
    }

    /**
     * Perform a EAP-MS-CHAP v2 4-way authentication against a list of servers.
     * Each server must share the same RADIUS secret.
     *
     * @see \Dapphp\Radius\Radius::accessRequestEapMsChapV2()
     * @see \Dapphp\Radius\Radius::accessRequestList()
     *
     * @param array $serverList Array of servers to authenticate against
     * @param string $username  The username to authenticate as
     * @param string $password  The plain text password that will be hashed using MS-CHAPv2
     * @return boolean          true if negotiation resulted in an Access-Accept packet, false otherwise
     */
    public function accessRequestEapMsChapV2List($serverList, $username, $password)
    {
        $result = false;

        if (!is_array($serverList)) {
            $this->errorCode    = 127;
            $this->errorMessage = sprintf(
                'server list passed to accessRequestEapMsChapV2List must be array; %s given', gettype($serverList)
            );

            return false;
        } elseif (empty($serverList)) {
            $this->errorCode    = 128;
            $this->errorMessage = 'server list passed to accessRequestEapMsChapV2List was empty';
        }

        $attributes = $this->getAttributesToSend(); // store base attributes

        foreach($serverList as $server) {
            $this->setServer($server);

            $result = $this->accessRequestEapMsChapV2($username, $password);

            if ($result === true) {
                break; // success
            } elseif ($this->getErrorCode() === self::TYPE_ACCESS_REJECT) {
                break; // access rejected
            } else {
                /* timeout or other possible transient error; try next host */
                $this->attributesToSend = $attributes; // reset base attributes
                $this->generateRequestAuthenticator(); // generate a new random request authenticator
            }
        }

        return $result;
    }

    /**
     * Send a RADIUS packet over the wire using UDP.
     *
     * @param string $packetData  The raw, complete, RADIUS packet to send
     * @return boolean|resource   false if the packet failed to send, or a socket resource on success
     */
    private function sendRadiusRequest($packetData, $port = null)
    {
        if (empty($this->server)) {
            $this->errorCode    = 1;
            $this->errorMessage = 'Server not set, cannot send RADIUS request';
            return false;
        }

        $packetLen = strlen($packetData);

        if (is_null($port)) {
            $port = $this->authenticationPort;
        }

        if ($this->debug) {
            $this->debugInfo("Connect to {$this->server}:{$port}");
        }
        $conn = @fsockopen('udp://' . $this->server, $port, $errno, $errstr);
        if (!$conn) {
            $this->errorCode    = $errno;
            $this->errorMessage = $errstr;
            return false;
        }

        $sent = fwrite($conn, $packetData);
        if (!$sent || $packetLen != $sent) {
            $this->errorCode    = 55; // CURLE_SEND_ERROR
            $this->errorMessage = 'Failed to send UDP packet';
            return false;
        }

        if ($this->debug) {
            $this->debugInfo(
                sprintf(
                    '<b>Packet type %d (%s) sent to %s</b>',
                    $this->radiusPacket,
                    $this->getRadiusPacketInfo($this->radiusPacket),
                    $this->server
                )
            );
            if (is_array($this->attributesToSend)) {
                foreach($this->attributesToSend as $attrs) {
                    if (!is_array($attrs)) {
                        $attrs = array($attrs);
                    }

                    foreach($attrs as $attr) {
                        $attrInfo = $this->getAttributesInfo(ord(substr($attr, 0, 1)));
                        $value = $this->decodeRadiusAttribute(substr($attr, 2), ord(substr($attr, 0, 1)));
                        // Match for most non-printable chars somewhat taking multibyte chars into account
                        if (preg_match('/[^\x09-\x0d\x1b\x20-\xff]/', $value) === 1) {
                            $value = '0x' . bin2hex($value);
                        }
                        $this->debugInfo(
                            sprintf(
                                'Attribute %d (%s), length (%d), format %s, value <em>%s</em>',
                                ord(substr($attr, 0, 1)),
                                $attrInfo[0],
                                ord(substr($attr, 1, 1)) - 2,
                                $attrInfo[1],
                                $value
                            )
                        );
                    }
                }
            }
        }

        return $conn;
    }

    /**
     * Wait for a UDP response packet and read using a timeout.
     *
     * @param resource $conn  The connection resource returned by fsockopen
     * @return boolean|string false on failure, or the RADIUS response packet
     */
    private function readRadiusResponse($conn)
    {
        stream_set_blocking($conn, false);
        $read    = array($conn);
        $write   = null;
        $except  = null;

        $receivedPacket = '';
        $packetLen      = null;
        $elapsed        = 0;

        do {
            // Loop until the entire packet is read.  Even with small packets,
            // not all data might get returned in one read on a non-blocking stream.

            $t0      = microtime(true);
            $changed = stream_select($read, $write, $except, $this->timeout);
            $t1      = microtime(true);

            if ($changed > 0) {
                $data = fgets($conn, 1024);
                // Try to read as much data from the stream in one pass until 4
                // bytes are read.  Once we have 4 bytes, we can determine the
                // length of the RADIUS response to know when to stop reading.

                if ($data === false) {
                    // recv could fail due to ICMP destination unreachable
                    $this->errorCode    = 56; // CURLE_RECV_ERROR
                    $this->errorMessage = 'Failure with receiving network data';
                    return false;
                }

                $receivedPacket .= $data;

                if (strlen($receivedPacket) < 4) {
                    // not enough data to get the size
                    // this will probably never happen
                    continue;
                }

                if ($packetLen == null) {
                    // first pass - decode the packet size from response
                    $packetLen = unpack('n', substr($receivedPacket, 2, 2));
                    $packetLen = (int)array_shift($packetLen);

                    if ($packetLen < 4 || $packetLen > 65507) {
                        $this->errorCode = 102;
                        $this->errorMessage = "Bad packet size in RADIUS response.  Got {$packetLen}";
                        return false;
                    }
                }

            } elseif ($changed === false) {
                $this->errorCode    = 2;
                $this->errorMessage = 'stream_select returned false';
                return false;
            } else {
                $this->errorCode    = 28; // CURLE_OPERATION_TIMEDOUT
                $this->errorMessage = 'Timed out while waiting for RADIUS response';
                return false;
            }

            $elapsed += ($t1 - $t0);
        } while ($elapsed < $this->timeout && strlen($receivedPacket) < $packetLen);

        return $receivedPacket;
    }

    /**
     * Parse a response packet and do some basic validation.
     *
     * @param string $packet  The raw RADIUS response packet
     * @return boolean  true if the packet was decoded, false otherwise.
     */
    private function parseRadiusResponsePacket($packet)
    {
        $this->radiusPacketReceived = ord(substr($packet, 0, 1));

        $this->debugInfo(sprintf(
            '<b>Packet type %d (%s) received</b>',
            $this->radiusPacketReceived,
            $this->getRadiusPacketInfo($this->getResponsePacket())
        ));

        if ($this->radiusPacketReceived > 0) {
            $this->identifierReceived = intval(ord(substr($packet, 1, 1)));
            $packetLenRx = unpack('n', substr($packet, 2, 2));
            $packetLenRx = array_shift($packetLenRx);
            $this->responseAuthenticator = bin2hex(substr($packet, 4, 16));
            if ($packetLenRx > 20) {
                $attrContent = substr($packet, 20);
            } else {
                $attrContent = '';
            }

            $authCheck = md5(
                substr($packet, 0, 4) .
                $this->getRequestAuthenticator() .
                $attrContent .
                $this->getSecret()
            );

            if ($authCheck !== $this->responseAuthenticator) {
                $this->errorCode    = 101;
                $this->errorMessage = 'Response authenticator in received packet did not match expected value';
                return false;
            }

            while (strlen($attrContent) > 2) {
                $attrType     = intval(ord(substr($attrContent, 0, 1)));
                $attrLength   = intval(ord(substr($attrContent, 1, 1)));
                $attrValueRaw = substr($attrContent, 2, $attrLength - 2);
                $attrContent  = substr($attrContent, $attrLength);
                $attrValue    = $this->decodeRadiusAttribute($attrValueRaw, $attrType);

                $attr = $this->getAttributesInfo($attrType);
                if (26 == $attrType) {
                    $vendorArr = $this->decodeVendorSpecificContent($attrValue);
                    foreach($vendorArr as $vendor) {
                        $value = $vendor[2];
                        // Match for most non-printable chars somewhat taking multibyte chars into account
                        if (preg_match('/[^\x09-\x0d\x1b\x20-\xff]/', $value) === 1) {
                            $value = '0x' . bin2hex($value);
                        }
                        $this->debugInfo(
                            sprintf(
                                'Attribute %d (%s), length %d, format %s, Vendor-Id: %d, Vendor-type: %s, Attribute-specific: %s',
                                $attrType, $attr[0], $attrLength - 2,
                                $attr[1], $vendor[0], $vendor[1], $value
                            )
                        );
                    }
                } else {
                    $value = $attrValue;
                    // Match for most non-printable chars somewhat taking multibyte chars into account
                    if (preg_match('/[^\x09-\x0d\x1b\x20-\xff]/', $value) === 1) {
                        $value = '0x' . bin2hex($value);
                    }
                    $this->debugInfo(
                        sprintf(
                            'Attribute %d (%s), length %d, format %s, value <em>%s</em>',
                            $attrType, $attr[0], $attrLength - 2, $attr[1], $value
                        )
                    );
                }

                // TODO: check message authenticator

                $this->attributesReceived[] = array($attrType, $attrValue);
            }
        } else {
            $this->errorCode    = 100;
            $this->errorMessage = 'Invalid response packet received';
            return false;
        }

        return true;
    }

    /**
     * Generate a RADIUS packet based on the set attributes and properties.
     * Generally, there is no need to call this function. Use one of the accessRequest*, accounting, or dynamic
     * authorization functions.
     *
     * @param string $authMode 'request' for RADIUS requests or 'accounting' for accounting requests.
     *
     * @return string The RADIUS packet
     */
    public function generateRadiusPacket(string $authMode = self::AUTH_REQUEST)
    {
        $includeMessageAuthenticator = false;

        // Build attribute payload and detect if Message-Authenticator (80) was requested
        $attrContent = '';
        if (is_array($this->attributesToSend)) {
            foreach ($this->attributesToSend as $attr) {
                if (is_array($attr)) {
                    // vendor-specific (multiple attributes)
                    $attrContent .= implode('', $attr);
                } elseif (ord($attr[0]) === 80) {
                    // Caller requested Message-Authenticator; we’ll append the computed one later
                    $includeMessageAuthenticator = true;
                } else {
                    $attrContent .= $attr;
                }
            }
        }

        // Build the 20-byte packet header with the code, id, placeholder length, and authenticator
        $packetData  = chr($this->radiusPacket);               // Code
        $packetData .= pack('C', $this->getNextIdentifier());  // Identifier
        $packetData .= pack('n', 0);                           // Length (placeholder for now)

        if ($authMode === self::AUTH_REQUEST) {
            // Access/Request: use request authenticator already set by the caller
            $packetData .= $this->getRequestAuthenticator();
        } elseif ($authMode === self::AUTH_ACCOUNTING) {
            // Accounting: 16 zero bytes, replaced with MD5 checksum later
            $packetData .= str_repeat("\x00", 16);
        } else {
            throw new \InvalidArgumentException('Unknown RADIUS authenticator mode: ' . $authMode);
        }

        // Add request attributes to the packet (without Message-Authenticator)
        $packetData .= $attrContent;

        // If Message-Authenticator is requested, append attribute 80 with 16 zero bytes
        if ($includeMessageAuthenticator) {
            // type(80) + length(18) + 16 zeroes
            $packetData .= chr(80) . chr(18) . str_repeat("\x00", 16);
        }

        // Finalize length now that we know the total packet length
        $length = pack('n', strlen($packetData));
        $packetData[2] = $length[0];
        $packetData[3] = $length[1];

        // If Message-Authenticator is present, compute and insert HMAC-MD5 over the entire packet
        //   - For access: it must include the real request authenticator
        //   - For accounting: it must include 16 zero bytes in the authenticator (as it currently is)
        if ($includeMessageAuthenticator) {
            $messageAuthenticator = hash_hmac('md5', $packetData, $this->secret, true);
            // Replace the last 16 bytes (we appended MA at the very end)
            for ($i = 0; $i < 16; ++$i) {
                $packetData[-16 + $i] = $messageAuthenticator[$i];
            }
        }

        // If accounting mode, compute and insert the real request authenticator over packet+secret
        if ($authMode === self::AUTH_ACCOUNTING) {
            $authenticator = md5($packetData . $this->secret, true);
            // Keep for verifying response authenticator in replies
            $this->setRequestAuthenticator($authenticator);
            // Overwrite authenticator field at bytes [4..19]
            for ($i = 0; $i < 16; ++$i) {
                $packetData[4 + $i] = $authenticator[$i];
            }
        }

        return $packetData;
    }

    /**
     * Set the RADIUS packet identifier that will be used for the next request
     *
     * @param int    $identifierToSend  The packet identifier to send
     * @return self
     */
    public function setNextIdentifier($identifierToSend = 0)
    {
        $id = (int)$identifierToSend;

        $this->identifierToSend = $id - 1;

        return $this;
    }

    /**
     * Increment the packet identifier and return the number
     *
     * @return int     The radius packet id
     */
    public function getNextIdentifier()
    {
        $this->identifierToSend = (($this->identifierToSend + 1) % 256);
        return $this->identifierToSend;
    }

    /**
     * Generate a random request authenticator for the next request.
     *
     * This only needs to be called when sending an access request more than once. A random request authenticator is
     * generated when a new Radius client is created. If multiple requests are sent with the same client object, a new
     * request authenticator should be generated for each subsequent request.
     *
     * @return self
     */
    public function generateRequestAuthenticator()
    {
        $this->requestAuthenticator = '';

        for ($c = 0; $c <= 15; ++$c) {
            $this->requestAuthenticator .= chr(rand(1, 255));
        }

        return $this;
    }

    /**
     * Set the request authenticator for the packet.  This is for testing only.
     * There is no need to ever call this function.
     *
     * @param string $requestAuthenticator  The 16 octet request identifier
     * @return boolean|self false if the authenticator is invalid length, self otherwise
     */
    public function setRequestAuthenticator($requestAuthenticator)
    {
        if (strlen($requestAuthenticator) != 16) {
            return false;
        }

        $this->requestAuthenticator = $requestAuthenticator;

        return $this;
    }

    /**
     * Get the value of the request authenticator used in request packets
     *
     * @return string  16 octet request authenticator
     */
    public function getRequestAuthenticator()
    {
        return $this->requestAuthenticator;
    }

    protected function clearDataToSend()
    {
        $this->radiusPacket     = 0;
        $this->attributesToSend = [];
        return $this;
    }

    protected function clearDataReceived()
    {
        $this->radiusPacketReceived = 0;
        $this->attributesReceived   = [];
        return $this;
    }

    public function setPacketType($type)
    {
        $this->radiusPacket = $type;
        return $this;
    }

    private function clearError()
    {
        $this->errorCode    = 0;
        $this->errorMessage = '';

        return $this;
    }

    protected function debugInfo($message)
    {
        if ($this->debug) {
            $msg = date('Y-m-d H:i:s'). ' DEBUG: ';
            $msg .= $message;
            $msg .= "<br>\n";

            if (php_sapi_name() == 'cli') {
                $msg = strip_tags($msg);
            }

            echo $msg;
            flush();
        }
    }

    private function decodeRadiusAttribute($rawValue, $attributeFormat)
    {
        $value = null;
        $attrInfo = $this->getAttributesInfo($attributeFormat);

        if (empty($attrInfo[1])) {
            return null;
        }

        $attrType = $attrInfo[1];

        if (array_key_exists($attrType, $this->dataTypeMap)) {
            $newDataType = $this->dataTypeMap[$attrType];
            $attrType = $newDataType;
        }

        switch ($attrType) {
            // integer
            case 1:
            case $this->radiusDataTypes[1]:
            // enum
            case 2:
            case $this->radiusDataTypes[2]:
                $tmp = unpack('Nnum', $rawValue);
                if (isset($tmp['num'])) {
                    $value = $tmp['num'];
                } else {
                    $value = null;
                }
                break;

            // time
            case 3:
            case $this->radiusDataTypes[3]:
                $value = unpack('Ntime', $rawValue);
                if ($value) {
                    $value = $value['time'];
                } else {
                    $value = null;
                }
                break;

            // text
            case 4:
            case $this->radiusDataTypes[4]:
            // string
            case 5:
            case $this->radiusDataTypes[5]:
                $value = $rawValue;
                break;

            case 6:
            case $this->radiusDataTypes[6]:
                $value = '';
                while (strlen($rawValue)) {
                    $value .= substr($rawValue, 0, 253);
                    $rawValue = substr($rawValue, 253);
                    $type = ord(substr($rawValue, 0, 1));
                    $len  = ord(substr($rawValue, 1, 1));
                    $rawValue = substr($rawValue, 2);
                }
                break;

            // ipv4address
            case 8:
            case $this->radiusDataTypes[8]:
            // ipv6address
            case 9:
            case $this->radiusDataTypes[9]:
                $value = inet_ntop($rawValue);
                break;

            // ipv6prefix
            case 10:
            case $this->radiusDataTypes[10]:
                $reserved = substr($rawValue, 0, 1);
                $prefixLen = ord(substr($rawValue, 1, 1));
                $prefix = substr($rawValue, 2);
                $addr = $prefix . str_repeat("\x00", 16 - strlen($prefix));
                $addr = inet_ntop($addr);
                $value = sprintf('%s/%d', $addr, $prefixLen);
                break;

            // ipv4prefix
            case 11:
            case $this->radiusDataTypes[11]:
                $reserved = substr($rawValue, 0, 1);
                $prefixLen = ord(substr($rawValue, 1, 1));
                $prefix = substr($rawValue, 2);
                $value = sprintf('%s/%d', inet_ntop($prefix), $prefixLen);
                break;

            // ifid
            case 7:
            case $this->radiusDataTypes[7]:
            // integer64
            case 12:
            case $this->radiusDataTypes[12]:
                $tmp = unpack('Jnum', $rawValue);
                $value = isset($tmp['num']) ? $tmp['num'] : null;
                break;

            default:
                // return raw bytes for other types
                $value = $rawValue;
                break;
        }

        return $value;
    }

    public function accountingRequest()
    {
        $this->clearDataReceived()
            ->clearError()
            ->setPacketType(self::TYPE_ACCOUNTING_REQUEST);

        $packetData = $this->generateRadiusPacket(self::AUTH_ACCOUNTING);

        $conn = $this->sendRadiusRequest($packetData, $this->accountingPort);
        if (!$conn) {
            $this->debugInfo(sprintf(
                    'Failed to send packet to %s; error: %s',
                    $this->server,
                    $this->getErrorMessage())
            );

            return false;
        }

        $receivedPacket = $this->readRadiusResponse($conn);
        @fclose($conn);

        if (!$receivedPacket) {
            $this->debugInfo(sprintf(
                    'Error receiving response packet from %s; error: %s',
                    $this->server,
                    $this->getErrorMessage())
            );

            return false;
        }

        if (!$this->parseRadiusResponsePacket($receivedPacket)) {
            $this->debugInfo(sprintf(
                    'Bad RADIUS response from %s; error: %s',
                    $this->server,
                    $this->getErrorMessage())
            );

            return false;
        }

        if ($this->radiusPacketReceived != self::TYPE_ACCOUNTING_RESPONSE) {
            $this->errorCode    = 3;
            $this->errorMessage = 'Response packet from RADIUS is not valid';
        }

        return (self::TYPE_ACCOUNTING_RESPONSE == ($this->radiusPacketReceived));
    }

    /**
     * Issue a Disconnect-Request packet to the RADIUS server.
     *
     * @param int    $timeout   The timeout (in seconds) to wait for a response packet
     * @return boolean          true if the server sent a CoA-Request packet, false otherwise
     */
    public function disconnectRequest($timeout = 0)
    {
        $this->clearDataReceived()
             ->clearError()
             ->setPacketType(self::TYPE_DISCONNECT_REQUEST);

        if (intval($timeout) > 0) {
            $this->setTimeout($timeout);
        }

        $packetData = $this->generateRadiusPacket(self::AUTH_ACCOUNTING);

        $conn = $this->sendRadiusRequest($packetData, $this->dynamicAuthorizationPort);
        if (!$conn) {
            $this->debugInfo(sprintf(
                'Failed to send packet to %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        $receivedPacket = $this->readRadiusResponse($conn);
        @fclose($conn);

        if (!$receivedPacket) {
            $this->debugInfo(sprintf(
                'Error receiving response packet from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if (!$this->parseRadiusResponsePacket($receivedPacket)) {
            $this->debugInfo(sprintf(
                'Bad RADIUS response from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if ($this->radiusPacketReceived == self::TYPE_DISCONNECT_NAK) {
            $this->errorCode    = 3;
            $this->errorMessage = 'Disconnect request failed (NAK)';
        }

        return (self::TYPE_DISCONNECT_ACK == ($this->radiusPacketReceived));
    }

    /**
     * Issue a CoA-Request packet to the RADIUS server.
     *
     * @param int    $timeout   The timeout (in seconds) to wait for a response packet
     * @return boolean          true if the server sent a CoA-Request packet, false otherwise
     */
    public function coaRequest($timeout = 0)
    {
        $this->clearDataReceived()
             ->clearError()
             ->setPacketType(self::TYPE_COA_REQUEST);

        if (intval($timeout) > 0) {
            $this->setTimeout($timeout);
        }

        $packetData = $this->generateRadiusPacket(self::AUTH_ACCOUNTING);

        $conn = $this->sendRadiusRequest($packetData, $this->dynamicAuthorizationPort);
        if (!$conn) {
            $this->debugInfo(sprintf(
                'Failed to send packet to %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        $receivedPacket = $this->readRadiusResponse($conn);
        @fclose($conn);

        if (!$receivedPacket) {
            $this->debugInfo(sprintf(
                'Error receiving response packet from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if (!$this->parseRadiusResponsePacket($receivedPacket)) {
            $this->debugInfo(sprintf(
                'Bad RADIUS response from %s; error: %s',
                $this->server,
                $this->getErrorMessage())
            );

            return false;
        }

        if ($this->radiusPacketReceived == self::TYPE_COA_NAK) {
            $this->errorCode    = 3;
            $this->errorMessage = 'CoA requested failed (NAK)';
        }

        return (self::TYPE_COA_ACK == ($this->radiusPacketReceived));
    }
}
