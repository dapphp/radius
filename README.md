<p align="center">
<a href="https://app.travis-ci.com/github/dapphp/radius"><img src="https://app.travis-ci.com/dapphp/radius.svg?branch=master" alt="Build Status"></a>
<a href="https://packagist.org/packages/dapphp/radius"><img src="https://poser.pugx.org/dapphp/radius/downloads" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/dapphp/radius"><img src="https://poser.pugx.org/dapphp/radius/v/stable" alt="Latest Stable Version"></a>
</p>

## Name

**Dapphp\Radius** – A pure PHP RADIUS client based on the SysCo/al implementation

## Author

* Drew Phillips <drew@drew-phillips.com>
* SysCo/al <developer@sysco.ch> (http://developer.sysco.ch/php/)

## Description

**Dapphp\Radius** is a pure PHP RADIUS client for authenticating users against
a RADIUS server in PHP.  It currently supports basic RADIUS auth using PAP,
CHAP (MD5), MSCHAP v1, MSCHAP v2, and EAP-MSCHAP v2, accounting (RFC 2866), and
Dynamic Authorization CoA and Disconnect requests (RFC 5176).

The library has been tested to work with the following RADIUS servers:

- Microsoft Windows Server 2019 Network Policy Server
- Microsoft Windows Server 2016 Network Policy Server
- Microsoft Windows Server 2012 Network Policy Server
- FreeRADIUS 2, 3, 3.2

PAP authentication has been tested on:

- Microsoft Radius server IAS
- Mideye RADIUS Server
- Radl
- RSA SecurID
- VASCO Middleware 3.0 server
- WinRadius
- ZyXEL ZyWALL OTP

The PHP openssl extension is required if using MSCHAP v1 or v2.  For older PHP
versions that have mcrypt without openssl support, then mcrypt is used.

## Installation

The recommended way to install `dapphp/radius` is using [Composer](https://getcomposer.org).
If you are already using composer, simple run `composer require dapphp/radius` or add
`dapphp/radius` to your composer.json file's `require` section.

For PHP 7.3 and later use the 3.x branch, and use the 2.x branch for PHP 7.2 and earlier.

Standalone installation is also supported and a SPL autoloader is provided.
(Don't use the standalone autoloader if you're using Composer!).

To install standalone, download the release archive and extract to a location
on your server.  In your application, `require_once 'radius/autoload.php';` and
then you can use the class.

## Examples

See the `examples/` directory for working examples. The RADIUS server address, secret, and credentials are read from
environment variables and default to:

    RADIUS_SERVER_ADDR=192.168.0.20
    RADIUS_USER=nemo
    RADIUS_PASS=arctangent
    RADIUS_SECRET=xyzzy5461

To print RADIUS debug info, specify the `-v` option.

Example:

    RADIUS_SERVER_ADDR=10.0.100.1 RADIUS_USER=radtest php example/client.php -v

## Synopsis

	<?php

	use Dapphp\Radius\Radius;

	require_once '/path/to/radius/autoload.php';
	// or, if using composer
	require_once '/path/to/vendor/autoload.php';

	$client = new Radius();

	// set server, secret, and basic attributes
	$client->setServer('12.34.56.78') // RADIUS server address
		->setSecret('radius shared secret')
		->setNasIpAddress('10.0.1.2')
		->setAttribute('NAS-Identifier, 'login')
		->setAttribute('NAS-Port', 3);

	// IPv6 address attributes
	$client->setAttribute('NAS-IPv6-Address', '2001:5a8:0:1::40b');

	// IPv6 prefix attributes
	$client->setAttribute('Framed-IPv6-Prefix', '2001:db8:85a3:1::/64');
	// or, a complete address with prefix length works the same
	$client->setAttribute('Framed-IPv6-Prefix', '2001:0db8:85a3:0001:000a:8a2e:0370:7334/64');

	// Data types in Radius (RFC 8044) and custom or non-built in attributes
	$client->addRadiusAttribute(250, 'Reserved-Attr-Test1', Radius::DATA_TYPE_STRING)
		->addRadiusAttribute(251, 'Reserved-Attr-Test2', Radius::DATA_TYPE_IPV4ADDR)
		->addRadiusAttribute(252, 'Reserved-Attr-Test3', Radius::DATA_TYPE_TIME)
		->addRadiusAttribute(253, 'Reserved-Attr-Test4', Radius::DATA_TYPE_CONCAT)
		->addRadiusAttribute(249, 'Reserved-Attr-Test5', Radius::DATA_TYPE_IFID);

	$strval = "This is a test string.`~1@3.?,/><][{}\|\\=+-_0)9(8*7&6^5%4\$3#2@1!";
	$testTime = strtotime('1998-01-01 00:00:01');
	$concat = str_repeat('A', 253) . str_repeat('B', 253) . str_repeat('C', 84);
	$testIfId = 0x0253a1fffe2c831f;

	$client->setAttribute('Reserved-Attr-Test1', $strval)
		->setAttribute('Reserved-Attr-Test2', '10.9.8.7')
		->setAttribute('Reserved-Attr-Test3', $testTime)
		->setAttribute('Reserved-Attr-Test4', $concat)
		->setAttribute('Reserved-Attr-Test5', $testIfId)
	;


	// PAP authentication; returns true if successful, false otherwise
	$authenticated = $client->accessRequest($username, $password);

	// CHAP-MD5 authentication
	$client->setChapPassword($password); // set chap password
	$authenticated = $client->accessRequest($username); // authenticate, don't specify pw here

	// MSCHAP v1 authentication
	$client->setMSChapPassword($password); // set ms chap password (uses openssl or mcrypt)
	$authenticated = $client->accessRequest($username);

	// MSCHAP v2 authentication (non-EAP)
	$client->setMsChapV2Password($username, $password);
	$authenticated = $client->accessRequest($username);

	// EAP-MSCHAP v2 authentication
	$authenticated = $client->accessRequestEapMsChapV2($username, $password);

	// Check authentication result
	if ($authenticated === false) {
		// false returned on failure
		echo sprintf(
			"Access-Request failed with error %d (%s).\n",
			$client->getErrorCode(),
			$client->getErrorMessage()
		);
	} else {
		// access request was accepted - client authenticated successfully
		echo "Success!  Received Access-Accept response from RADIUS server.\n";
		if (!empty($reply = $client->getReceivedAttribute('Reply-Message')) {
			echo "Reply: $reply\n";
		}
	}

## Supported data types

[RFC 8044](https://www.rfc-editor.org/rfc/rfc8044.html) defines consistent names and data types for RADIUS attribute
values. Version 3.1.0 added support for most data types and for mapping new attributes to these types.

The following types are supported:

* 1: integer - `Radius::DATA_TYPE_INTEGER`
* 2: enum - `Radius::DATA_TYPE_ENUM`
* 3: time - `Radius::DATA_TYPE_TIME`
* 4: text - `Radius::DATA_TYPE_TEXT`
* 5: string - `Radius::DATA_TYPE_STRING`
* 6: concat - `Radius::DATA_TYPE_CONCAT`
* 7: ifid - `Radius::DATA_TYPE_IFID`
* 8: ipv4addr - `Radius::DATA_TYPE_IPV4ADDR`
* 9: ipv6addr - `Radius::DATA_TYPE_IPV6ADDR`
* 10: ipv6prefix - `Radius::DATA_TYPE_IPV6PREFIX`
* 11: ipv4prefix - `Radius::DATA_TYPE_IPV4PREFIX`
* 12: integer64 - `Radius::DATA_TYPE_INTEGER64`
* 13: tlv - **UNSUPPORTED** `Radius::DATA_TYPE_TLV`
* 14: vsa - `Radius::DATA_TYPE_VSA`
* 15: extended - **UNSUPPORTED** `Radius::DATA_TYPE_EXTENDED`
* 16: long-extended - **UNSUPPORTED** `Radius::DATA_TYPE_LONG_EXTENDED`
* 17: evs - **UNSUPPORTED** `Radius::DATA_TYPE_LONG_EVS`

## Advanced Usage

This section provides additional information and examples for advanced usage of the RADIUS client.

### Authenticating against a RADIUS cluster

For clustered setups with more than one RADIUS server, use the `accessRequestList` method to send authentication
requests to multiple servers in a failover configuration. This ensures that if one server is unavailable, the client can
attempt authentication with another server in the list. Each server in the list is tried until authentication is
accepted or rejected. The client secret must be the same for all servers in the list.

	// Try each server in the list until acceptance or rejection. Set the secret and any required attributes first.

	$servers = [ 'server1.radius.domain', 'server2.radius.domain' ];
	// or
	$servers = gethostbynamel("radius.site.domain"); // gets list of IPv4 addresses to a given host

    // shuffle($servers); // optionally, randomize the order of servers

	$authenticated = $client->accessRequestList($servers, $username, $password);
	// or
	$authenticated = $client->accessRequestEapMsChapV2List($servers, $username, $password);

### Re-using the same client to send multiple access requests

In situations where the same RADIUS client needs to send multiple access requests to a RADIUS server, a random
request authenticator should be generated for each request to ensure uniqueness and prevent replay attacks. Use this
when sending multiple access requests with the same client before calling `accessRequest` again:

    $client->generateRequestAuthenticator();

This is done automatically if using the `accessRequestList` or `accessRequestEapMsChapV2List` methods.

### IPv6 Server Support

If the operating system is configured for IPv6 and the RADIUS server supports IPv6, the client can send requests to the
server using IPv6 addresses or hostnames that resolve to IPv6 addresses.

To explicitly set the server address to an IPv6 address, specify the address when creating the client or using the
`setServer()` method. Note, IPv6 addresses must be enclosed in square brackets. If the v6 address is not enclosed in
square brackets, they will be added automatically.

    $client = new Radius('[fd00:b5a6:6c19:6bf7::1001]');
    // or
    $client->setServer('[fd00:b5a6:6c19:6bf7::1001]');

### Mixing IPv4 and IPv6 addresses in a clustered setup

In situations where the RADIUS hostname resolves to both IPv4 and IPv6 addresses, use `accessRequestList()` to send
requests to each address type. Either supply a list of explicit IPv4 and IPv6 addresses, or, use the following code to
automatically resolve the hostname to both address types:

    // List of specific addresses
    $servers = [
        'radius.local', // Tries radius.local, depending on how the DNS resolves it
        '10.0.100.100', // Next address in the list
        'fd00:b5a6:6c19:6bf7:10:0:100:100', // Next address in the list
        '[fd00:b5a6:6c19:6bf7:10:0:200:200]', // Next address, square bracket notation
    ];

    // Resolve hostname to multiple IPv4 and/or IPv6 addresses
    // If the 'sockets' extension is loaded, use socket_addrinfo_lookup, otherwise, fall back to dns_get_record.
    // socket_addrinfo_lookup is preferred as it will honor `hosts` files and system DNS configuration

    if (extension_loaded('sockets')) {
        $servers = array_merge(...array_map(function ($family) use ($server) {
            return array_map(function ($addrInfo) {
                $addrArray = socket_addrinfo_explain($addrInfo);
                return $addrArray['ai_addr']['sin6_addr'] ?? $addrArray['ai_addr']['sin_addr'];
            }, socket_addrinfo_lookup($server, null, ['ai_family' => $family, 'ai_socktype' => SOCK_DGRAM]) ?: []);
        }, [AF_INET6, AF_INET]));
    } else {
        $servers = array_map(function ($dnsRecord) {
            return $dnsRecord['ipv6'] ?? $dnsRecord['ip'];
        }, dns_get_record($server, DNS_AAAA | DNS_A));
    }

    // Now, authenticate using the resolved addresses
    $authenticated = $client->accessRequestList($servers, $username, $password);

### Setting vendor-specific attributes

Vendor IDs are defined in the `\Dapphp\Radius\VendorId` class. For example, `\Dapphp\Radius\VendorId::MIKROTIK`.

    // Set vendor-specific attribute $attributeNumber for $vendorId
	$client->setVendorSpecificAttribute($vendorId, $attributeNumber, $rawValue);

	// Setting a vendor-specific attribute with other data types
	$client->setVendorSpecificAttribute($vendorId, $attributeNumber, $ipv4addr, Radius::DATA_TYPE_IPV4ADDR);
	$client->setVendorSpecificAttribute($vendorId, $attributeNumber, $ipv6addr, Radius::DATA_TYPE_IPV6ADDR);
	$client->setVendorSpecificAttribute($vendorId, $attributeNumber, $int64, Radius::DATA_TYPE_INTEGER64);

### Retrieving attributes from RADIUS responses

To get attributes from received replies, use the `getAttribute()` method. This method returns the value of the specified
attribute from the last received RADIUS response.

	$value = $client->getAttribute('Error-Cause');
	$reply = $client->getAttribute('Reply-Message');
	$ipv6addr = $client->getAttribute('Framed-IPv6-Address');

	// Get an array of all received attributes
	$attributes = getReceivedAttributes();

### Debugging requests and replies

Before sending a request, call the `setDebug()` method. The client will output debug information showing what attributes
are set, sent, and received as well as information about the requests and responses.

	$client->setDebug(true); // enable debug output on console


## Requirements

* PHP 7.3, 8.x

## TODO

- Vendor specific attribute dictionaries

## Copyright

    Copyright (c) 2008, SysCo systemes de communication sa
    SysCo (tm) is a trademark of SysCo systemes de communication sa
    (http://www.sysco.ch/)
    All rights reserved.

    Copyright (c) 2016-2026, Drew Phillips
    (https://drew-phillips.com)

    Pure PHP radius class is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    Pure PHP radius class is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with Pure PHP radius class.
    If not, see <http://www.gnu.org/licenses/>

## Licenses

This library makes use of the Crypt_CHAP PEAR library.  See `lib/Pear_CHAP.php`.

	Copyright (c) 2002-2010, Michael Bretterklieber <michael@bretterklieber.com>
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	3. The names of the authors may not be used to endorse or promote products
	   derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
	IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
	INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
	BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
	OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
	EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	This code cannot simply be copied and put under the GNU Public License or
	any other GPL-like (LGPL, GPL2) License.
