<?php

use Dapphp\Radius\Radius;
use Dapphp\Radius\EAPPacket;
use Dapphp\Radius\MsChapV2Packet;
use Dapphp\Radius\VendorId;

use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    public function testSetAttributes()
    {
        $client = new Radius();

        $client->setAttribute(1, '');
        $attr = $client->getAttributesToSend(1);
        $this->assertEquals('', $attr);
        $client->resetAttributes();

        $client->setAttribute(1, "\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5");
        $attr = $client->getAttributesToSend(1);
        $this->assertEquals("κόσμε", $attr);
        $client->resetAttributes();

        // string value test
        $test   = 'this is a test';

        $client->setAttribute(80, $test);
        $attr   = $client->getAttributesToSend(80);
        $this->assertEquals($test, $attr);

        $client->removeAttribute(80);
        $attr   = $client->getAttributesToSend(80);
        $this->assertEquals(null, $attr);

        // integer value test
        $nasPort = 32768;

        $client->setAttribute(5, $nasPort);
        $attr   = $client->getAttributesToSend(5);
        $this->assertEquals($nasPort, $attr);

        $client->removeAttribute(5);
        $attr   = $client->getAttributesToSend(5);
        $this->assertEquals(null, $attr);

        $client->setAttribute(95, '2001:5a8:0:1::40b');
        $attr = $client->getAttributesToSend(95);
        $this->assertEquals('2001:5a8:0:1::40b', $attr);
        $client->removeAttribute(95);

        $client->setAttribute(55, 802598400);
        $attr = $client->getAttributesToSend(55);
        $this->assertEquals(802598400, $attr);
        $client->removeAttribute(55);

        if (PHP_INT_SIZE > 4) {
            $client->addRadiusAttribute(254, 'Test-Integer64', 'integer64');
            $client->setAttribute(254, 0x1234567887654321);
            $attr = $client->getAttributesToSend(254);
            $this->assertEquals(0x1234567887654321, $attr);
        }
    }

    public function testSetAttributesByName()
    {
        // String
        $client = new Radius();
        $client->setAttribute('User-Name', 'nemo');
        $attr = $client->getAttributesToSend()[0];
        $this->assertEquals(1, ord(substr($attr, 0, 1)));  // Attribute type 1 = username
        $this->assertEquals(6, ord(substr($attr, 1, 1)));
        $this->assertEquals('nemo', substr($attr, 2));
        $client->resetAttributes();

        // ipv4addr
        $ipv4addr = '10.100.1.111';
        $client->setAttribute('NAS-IP-Address', $ipv4addr);
        $ip = explode('.', $ipv4addr);
        $attr = $client->getAttributesToSend()[0];
        $this->assertEquals(4, ord(substr($attr, 0, 1)));  // Attribute type 4 = Nas-IP-Address
        $this->assertEquals(6, ord(substr($attr, 1, 1)));
        $this->assertEquals(chr($ip[0]) . chr($ip[1]) . chr($ip[2]) . chr($ip[3]), substr($attr, 2));
        $client->resetAttributes();

        // ipv4prefix
        $ipv4addr = '10.172.42.1';
        $ipv4prefix = '20';
        $ipv4prefix = $ipv4addr . '/' . $ipv4prefix;
        $attr = $client->encodeRadiusAttribute(155, $ipv4prefix, Radius::DATA_TYPE_IPV4PREFIX);
        $this->assertEquals(155, ord(substr($attr, 0, 1)));
        $this->assertEquals(8, ord(substr($attr, 1, 1)));
        $this->assertEquals(0, ord(substr($attr, 2, 1)));
        $this->assertEquals(20, ord(substr($attr, 3, 1)));
        $this->assertEquals('10.172.32.0', inet_ntop(substr($attr, 4)));

        // integer
        $client->setAttribute('Session-Timeout', 21600);
        $attr = $client->getAttributesToSend()[0];
        $this->assertEquals(27, ord(substr($attr, 0, 1)));  // Attribute type 27 = Session-Timeout
        $this->assertEquals(6, ord(substr($attr, 1, 1)));
        $this->assertEquals(21600, unpack('N', substr($attr, 2, 4))[1]);
        $client->resetAttributes();

        // ipv6addr
        $ipv6addr = '2001:db8:85a3::8a2e:370:7334';
        $client->setAttribute('NAS-IPv6-Address', $ipv6addr);
        $attr = $client->getAttributesToSend()[0];
        $this->assertEquals(95, ord(substr($attr, 0, 1)));  // Attribute type 95 = NAS-IPv6-Address
        $this->assertEquals(18, ord(substr($attr, 1, 1)));
        $this->assertEquals($ipv6addr, inet_ntop(substr($attr, 2, 16)));
        $client->resetAttributes();

        // ipv6prefix
        $ipv6addr   = '2001:0db8:85a3:0001:000a:8a2e:0370:7334';
        $prefixLen  = 64;
        $ipv6prefix = $ipv6addr .'/' . $prefixLen;
        $client->setAttribute('Framed-IPv6-Prefix', $ipv6prefix);
        $attr = $client->getAttributesToSend()[0];
        $this->assertEquals(97, ord(substr($attr, 0, 1)));  // Attribute type 97 = Framed-IPv6-Prefix
        $this->assertEquals(2 + 1 + 1 + (16 - (128 - $prefixLen) / 8), ord(substr($attr, 1, 1)));
        $this->assertEquals(0, ord(substr($attr, 2, 1)));  // Reserved bit
        $this->assertEquals($prefixLen, ord(substr($attr, 3, 1)));
        $this->assertEquals('2001:db8:85a3:1::', inet_ntop(substr($attr, 4) . str_repeat("\x00", 16 - (128 - $prefixLen) / 8)));
        $client->resetAttributes();

        if (PHP_INT_SIZE > 4) {
            // integer64
            $client->setAttribute('Framed-Interface-Id', 0x1234567887654321);
            $attr = $client->getAttributesToSend()[0];
            $this->assertEquals(96, ord(substr($attr, 0, 1)));  // Attribute type 96 = Framed-Interface-Id
            $this->assertEquals(10, ord(substr($attr, 1, 1)));
            $this->assertEquals(0x1234567887654321, unpack('J', substr($attr, 2, 8))[1]);
        }
    }

    public function testGetAttributes()
    {
        $client   = new Radius();
        $username = 'LinusX2@arpa.net';
        $nasIp    = '192.168.88.1';
        $nasPort  = 64000;

        $expected = ''; // manually constructed hex string
        $expected .= chr(1); // username
        $expected .= chr(2 + strlen($username)); // length
        $expected .= $username;

        $expected .= chr(4); // nas ip
        $expected .= chr(6);
        $expected .= pack('N', ip2long($nasIp));

        $expected .= chr(5); // nas port
        $expected .= chr(6);
        $expected .= pack('N', $nasPort);


        $client->setUsername($username)
               ->setNasIPAddress($nasIp)
               ->setNasPort($nasPort);

        $actual = implode('', $client->getAttributesToSend());

        $this->assertEquals($expected, $actual);
        $this->assertEquals($username, $client->getAttributesToSend(1));
        $this->assertEquals($nasIp, $client->getAttributesToSend(4));
        $this->assertEquals($nasPort, $client->getAttributesToSend(5));
    }

    public function testAddRadiusAttribute()
    {
        $client = new Radius();

        $client->addRadiusAttribute(250, 'Reserved-Attr-Test', Radius::DATA_TYPE_STRING)
            ->addRadiusAttribute(251, 'Reserved-Attr-Test2', Radius::DATA_TYPE_IPV4ADDR)
            ->addRadiusAttribute(252, 'Reserved-Attr-Test3', Radius::DATA_TYPE_TIME)
            ->addRadiusAttribute(253, 'Reserved-Attr-Test4', Radius::DATA_TYPE_CONCAT)
            ->addRadiusAttribute(249, 'Reserved-Attr-Test5', Radius::DATA_TYPE_IFID);
        ;

        $testStr = "This is a test string.`~1@3.?,/><][{}\|\\=+-_0)9(8*7&6^5%4\$3#2@1!";
        $concatStringTest = str_repeat('A', 253) . str_repeat('B', 253) . str_repeat('C', 84);
        $testTime = strtotime('1998-01-01 00:00:01');
        $testIfId = 0x0253a1fffe2c831f;

        $client->setAttribute(250, $testStr)
            ->setAttribute(253, $concatStringTest)
            ->setAttribute(251, '10.9.8.7')
            ->setAttribute(252, $testTime)
            ->setAttribute(249, $testIfId)
        ;

        $attr = $client->getAttributesToSend(253);
        $this->assertEquals($concatStringTest, $attr);

        $packet = $client->generateRadiusPacket();
        $attrs  = substr($packet, 20);

        // string
        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data = substr($attrs, 2, $len - 2);

        $this->assertEquals(250, $type);
        $this->assertEquals(strlen($testStr), $len - 2);
        $this->assertEquals($testStr, $data);

        // concat string
        $attrs = substr($attrs, $len);

        // attr 1/3
        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data = substr($attrs, 2, $len - 2);
        $attrs = substr($attrs, $len);

        $this->assertEquals(253, $type);
        $this->assertEquals(253, $len - 2);

        // attr 2/3
        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data .= substr($attrs, 2, $len - 2);
        $attrs = substr($attrs, $len);

        $this->assertEquals(253, $type);
        $this->assertEquals(253, $len - 2);

        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data .= substr($attrs, 2, $len - 2);
        $attrs = substr($attrs, $len);

        $this->assertEquals(253, $type);
        $this->assertEquals(84, $len - 2);
        $this->assertEquals($concatStringTest, $data);

        // ipv4addr

        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data = substr($attrs, 2, $len - 2);

        $this->assertEquals(251, $type);
        $this->assertEquals(4, $len - 2);
        $this->assertEquals('10.9.8.7', inet_ntop($data));
        $attrs = substr($attrs, $len);

        // time

        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data = substr($attrs, 2, $len - 2);

        $this->assertEquals(252, $type);
        $this->assertEquals(4, $len - 2);
        $this->assertEquals($testTime, array_values(unpack('N', $data))[0]);
        $attrs = substr($attrs, $len);

        // ifid
        $type = ord(substr($attrs, 0, 1));
        $len  = ord(substr($attrs, 1, 1));
        $data = substr($attrs, 2, $len - 2);

        $this->assertEquals(249, $type);
        $this->assertEquals(8, $len - 2);
        $this->assertEquals($testIfId, array_values(unpack('J', $data))[0]);
        $attrs = substr($attrs, $len);

    }

    public function testVendorSpecificAttribute()
    {
        $client = new Radius();

        $client->setVendorSpecificAttribute(VendorId::MIKROTIK, 9, "69");
        $this->assertEquals(1, count($client->getAttributesToSend()));

        $this->assertEquals(26, ord(substr($client->getAttributesToSend()[0][0], 0, 1)));
        $it = $client->getAttributesToSend(26, 0);
        $this->assertNotNull($it);
        $decoded = $client->decodeVendorSpecificContent($it)[0];
        $this->assertEquals(VendorId::MIKROTIK, $decoded[0]);
        $this->assertEquals(9, $decoded[1]);
        $this->assertEquals("69", $decoded[2]);


        $client->setVendorSpecificAttribute(VendorId::MIKROTIK, 10, "420");
        $this->assertEquals(1, count($client->getAttributesToSend()));
        $this->assertEquals(26, ord(substr($client->getAttributesToSend()[0][1], 0, 1)));
        $it = $client->getAttributesToSend(26, 1);
        $this->assertNotNull($it);

        $decoded = $client->decodeVendorSpecificContent($it)[0];
        $this->assertEquals(VendorId::MIKROTIK, $decoded[0]);
        $this->assertEquals(10, $decoded[1]);
        $this->assertEquals("420", $decoded[2]);

        $client->resetAttributes();

        $client->setVendorSpecificAttribute(VendorId::ALCATEL_LUCENT_AAA, 11, "1.2.3.4", 'ipv4addr');
        $attr = $client->getAttributesToSend()[0][0];

        $this->assertEquals(26, ord(substr($attr, 0, 1)));  // type 26
        $this->assertEquals(12, ord(substr($attr, 1, 1)));  // length
        $this->assertEquals(VendorId::ALCATEL_LUCENT_AAA, unpack('N', (substr($attr, 2, 4)))[1]);
        $this->assertEquals(11, ord(substr($attr, 6, 1)));  // vendor type
        $this->assertEquals(2 + 4, ord(substr($attr, 7, 1)));  // vendor length
        $this->assertEquals('1.2.3.4', inet_ntop(substr($attr, 8)));      // value

        $client->setVendorSpecificAttribute(\Dapphp\Radius\VendorId::MIKROTIK, 10, "8.4.2.1", 'ipv4addr');  // Host-IP
        $attr = $client->getAttributesToSend()[0][1];

        $this->assertEquals(26, ord(substr($attr, 0, 1)));  // type 26
        $this->assertEquals(12, ord(substr($attr, 1, 1)));  // length
        $this->assertEquals(VendorId::MIKROTIK, unpack('N', (substr($attr, 2, 4)))[1]);
        $this->assertEquals(10, ord(substr($attr, 6, 1)));  // vendor type
        $this->assertEquals(2 + 4, ord(substr($attr, 7, 1)));  // vendor length
        $this->assertEquals('8.4.2.1', inet_ntop(substr($attr, 8)));      // value

        $client->setVendorSpecificAttribute(\Dapphp\Radius\VendorId::MIKROTIK, 13, 1192921436, 'integer');
        $attr = $client->getAttributesToSend()[0][2];
        $this->assertEquals(26, ord(substr($attr, 0, 1)));  // type 26
        $this->assertEquals(12, ord(substr($attr, 1, 1)));  // length
        $this->assertEquals(VendorId::MIKROTIK, unpack('N', (substr($attr, 2, 4)))[1]);
        $this->assertEquals(13, ord(substr($attr, 6, 1)));  // vendor type
        $this->assertEquals(2 + 4, ord(substr($attr, 7, 1)));  // vendor length
        $this->assertEquals(1192921436, unpack('N', substr($attr, 8))[1]);      // value

    }

    public function testEncryptedPassword()
    {
        $pass   = 'arctangent';
        $secret = 'xyzzy5461';
        $requestAuthenticator = "\x0f\x40\x3f\x94\x73\x97\x80\x57\xbd\x83\xd5\xcb\x98\xf4\x22\x7a";
        $client = new Radius();

        $expected  = "\x0d\xbe\x70\x8d\x93\xd4\x13\xce\x31\x96\xe4\x3f\x78\x2a\x0a\xee";
        $encrypted = $client->getEncryptedPassword($pass, $secret, $requestAuthenticator);

        $this->assertEquals($expected, $encrypted);
    }

    public function testEncryptedPassword2()
    {
        $pass   = 'm1cr0$ofT_W1nDoWz*';
        $secret = '%iM8WD3(9bSh4jXNyOH%4W6RE1s4bfQ#0h*n^lOz';
        $requestAuthenticator = "\x7d\x22\x56\x6c\x9d\x2d\x50\x26\x88\xc5\xb3\xf9\x33\x77\x14\x55";
        $client = new Radius();

        $expected = "\x44\xe0\xac\xdc\xed\x56\x39\x67\xb1\x41\x90\xef\x3e\x10\xca\x2c\xb5\xb0\x5f\xf6\x6c\x31\x87\xf0\x2a\x92\xcb\x65\xeb\x97\x31\x1f";
        $encrypted = $client->getEncryptedPassword($pass, $secret, $requestAuthenticator);

        $this->assertEquals($expected, $encrypted);
    }

    public function testCryptCHAPMSv1()
    {
        $pass = "Don't forget to bring a passphrase!";

        $chap            = new \Crypt_CHAP_MSv1();
        $chap->password  = $pass;
        $chap->chapid    = 42;
        $chap->challenge = "\x6c\x7e\x0d\xba\xe3\x81\xea\x51";

        try {
            $response = $chap->ntChallengeResponse();
        } catch (\Exception $ex) {
            if (stripos($ex->getMessage(), 'dec-ecb cipher is not supported by OpenSSL') !== false) {
                $this->markAsRisky();
                $this->markTestIncomplete('The PHP OpenSSL version does not support dec-ecb');
                return;
            }
            throw $ex;
        }

        $this->assertEquals('5f169b7d8176516f8092bce99008e097febfed2f043ec04e', bin2hex($response));
    }

    public function testCryptCHAPMSv1Indirect()
    {
        // Ensure Pear_CHAP_MSv1 can be loaded by Radius and that setting the attributes works

        $pass   = "This is ms-chap ~~++";
        $chal   = "\x02\x04\x08\x10\x20\x40\x80\x00"; // 8 byte 'random' challenge
        $client = new Radius();

        try {
            $client->setMsChapPassword($pass, $chal);
        } catch (\Exception $ex) {
            if (stripos($ex->getMessage(), 'dec-ecb cipher is not supported by OpenSSL') !== false) {
                $this->markAsRisky();
                $this->markTestIncomplete('The PHP OpenSSL version does not support dec-ecb');
                return;
            }
            throw $ex;
        }

        $chapChallenge = $client->getAttributesToSend(26);

        $vendor = unpack('NID', substr($chapChallenge, 0, 4));
        $type   = ord(substr($chapChallenge, 4, 1));
        $length = ord(substr($chapChallenge, 5, 1));
        $data   = substr($chapChallenge, 6, $length);

        $this->assertEquals(VendorId::MICROSOFT, $vendor['ID']);
        $this->assertEquals(11, $type); // chap challenge
        $this->assertEquals($chal, $data);
    }

    public function testCryptCHAPMSv2()
    {
        $pass = 'Passwords < Passphrases < $whatsNext?';

        $chap = new \Crypt_CHAP_MSv2();
        $chap->username      = 'nemo';
        $chap->password      = $pass;
        $chap->chapid        = 37;
        $chap->authChallenge = "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10";
        $chap->peerChallenge = "\x93\xa8\x14\xc3\x90\x4e\x67\xcc\xb1\xd2\x72\x23\xd5\xf3\x90\xae";

        try {
            $response = $chap->challengeResponse();
        } catch (\Exception $ex) {
            if (stripos($ex->getMessage(), 'dec-ecb cipher is not supported by OpenSSL') !== false) {
                $this->markAsRisky();
                $this->markTestIncomplete('The PHP OpenSSL version does not support dec-ecb');
                return;
            }
            throw $ex;
        }

        $this->assertEquals('a3d12ce2f52d13fe04421205a2ce17b0e559ea8a9e594c1c', bin2hex($response));
    }

    public function testAuthenticationPacket()
    {
        $user    = 'nemo';
        $pass    = 'arctangent';
        $secret  = 'xyzzy5461';
        $nas     = '192.168.1.16';
        $nasPort = 3;

        $client  = new Radius();

        $client->setRequestAuthenticator("\x0f\x40\x3f\x94\x73\x97\x80\x57\xbd\x83\xd5\xcb\x98\xf4\x22\x7a");

        $client->setPacketType(Radius::TYPE_ACCESS_REQUEST)
               ->setSecret($secret)
               ->setUsername($user)
               ->setPassword($pass)
               ->setNasIPAddress($nas)
               ->setNasPort($nasPort);

        $packet   = $client->generateRadiusPacket();
        $pwEnc    = "\x0d\xbe\x70\x8d\x93\xd4\x13\xce\x31\x96\xe4\x3f\x78\x2a\x0a\xee";
        $expected = "\x01\x00\x00\x38\x0f\x40\x3f\x94\x73\x97\x80\x57\xbd\x83"
                  . "\xd5\xcb\x98\xf4\x22\x7a\x01\x06\x6e\x65\x6d\x6f\x02\x12"
                  . $pwEnc
                  . "\x04\x06\xc0\xa8\x01\x10\x05\x06\x00\x00\x00\x03";

        $this->assertEquals($expected, $packet);
    }

    public function testFramedAuthPacket()
    {
        $user    = 'flopsy';
        $pass    = 'arctangent';
        $reqAuth = "\x2a\xee\x86\xf0\x8d\x0d\x55\x96\x9c\xa5\x97\x8e\x0d\x33\x67\xa2";
        $nas     = '192.168.1.16';
        $nasPort = 20;

        $expected = "\x01\x01\x00\x47\x2a\xee\x86\xf0\x8d\x0d\x55\x96\x9c\xa5"
                   ."\x97\x8e\x0d\x33\x67\xa2\x01\x08\x66\x6c\x6f\x70\x73\x79"
                   ."\x03\x13\x16\xe9\x75\x57\xc3\x16\x18\x58\x95\xf2\x93\xff"
                   ."\x63\x44\x07\x72\x75\x04\x06\xc0\xa8\x01\x10\x05\x06\x00"
                   ."\x00\x00\x14\x06\x06\x00\x00\x00\x02\x07\x06\x00\x00\x00\x01";

        $client = new Radius();
        $client->getNextIdentifier(); // increment to 1 for test
        $client->setChapId(22);
        $client->setRequestAuthenticator($reqAuth)
               ->setPacketType(Radius::TYPE_ACCESS_REQUEST)
               ->setUsername($user)
               ->setChapPassword($pass)
               ->setNasIPAddress($nas)
               ->setNasPort($nasPort)
               ->setAttribute(6, 2)  // service type (6) = framed (2)
               ->setAttribute(7, 1); // framed protocol (7) = ppp (1)

        $packet = $client->generateRadiusPacket();

        $this->assertEquals($expected, $packet);
    }

    public function testHmacMd5()
    {
        $str  = hex2bin('01870082093e4ad125399f8ac4ba6b00ab69a04001066e656d6f04067f0000010506000000145012000000000000000000000000000000001a10000001370b0a740c7921e45e91391a3a00000137013400010000000000000000000000000000000000000000000000004521bd46aebfd2ab3ec21dd6e6bbfa2e4ff325eab720fe37');
        $hash = hash_hmac('md5', $str, 'xyzzy5461', true);

        $expected = '48a3704ac91e8191497a1f3f213eb338';
        $actual   = bin2hex($hash);

        $this->assertEquals($expected, $actual);
    }

    public function testMsChapV1Packet()
    {
        $reqId   = 135;
        $user    = 'nemo';
        $pass    = 'arctangent123$';
        $secret  = 'xyzzy5461';
        $reqAuth = "\x09\x3e\x4a\xd1\x25\x39\x9f\x8a\xc4\xba\x6b\x00\xab\x69\xa0\x40";
        $nas     = '127.0.0.1';
        $nasPort = 20;
        $challenge = "\x74\x0c\x79\x21\xe4\x5e\x91\x39";

        $client = new Radius();
        $client->setPacketType(Radius::TYPE_ACCESS_REQUEST)
               ->setNextIdentifier($reqId)
               ->setRequestAuthenticator($reqAuth)
               ->setSecret($secret)
               ->setUsername($user)
               ->setNasIPAddress($nas)
               ->setNasPort($nasPort)
               ->setIncludeMessageAuthenticator(true)
        ;

        try {
            $client->setMsChapPassword($pass, $challenge);
        } catch (\Exception $ex) {
            if (stripos($ex->getMessage(), 'dec-ecb cipher is not supported by OpenSSL') !== false) {
                $this->markAsRisky();
                $this->markTestIncomplete('The PHP OpenSSL version does not support dec-ecb');
                return;
            }
            throw $ex;
        }

        $packet = $client->generateRadiusPacket();
        $packet = bin2hex($packet);

        $messageAuthenticator = substr($packet, -34); // extract message authenticator from the end of the packet
        $chapResponseIndex    = strpos($packet, "01370134"); // find the position of the chap ID (after vendor 311, flag 01, length 52)
        $chapId               = substr($packet, $chapResponseIndex + 8, 2); // random byte

        $expected = "01870082093e4ad125399f8ac4ba6b00ab69a04001066e656d6f04067f0000010506000000141a10000001370b0a740c7921e45e91391a3a000001370134ZZ010000000000000000000000000000000000000000000000004521bd46aebfd2ab3ec21dd6e6bbfa2e4ff325eab720fe3750";
        $expected = str_replace('ZZ', $chapId, $expected); // Replace the placeholder with the random chap ID
        $expected .= $messageAuthenticator; // Replace the message authenticator with the actual one

        $this->assertEquals($expected, $packet);
    }

    public function testEapPacketBasic()
    {
        $p = new MsChapV2Packet();
        $p->opcode = MsChapV2Packet::OPCODE_SUCCESS;
        $s = $p->__toString();

        $this->assertEquals("\x03", $s, "MsChapV2Packet success returns 0x03 without error");

        $p       = new EAPPacket();
        $p->code = EAPPacket::CODE_REQUEST;
        $p->id   = 111;
        $p->type = EAPPacket::TYPE_IDENTITY;
        $p->data = 'here is some data';

        $expected = "016f0016016865726520697320736f6d652064617461";

        $this->assertEquals($expected, bin2hex($p->__toString()));

        $parsed = EAPPacket::fromString($p->__toString());

        $this->assertEquals(EAPPacket::CODE_REQUEST, $parsed->code);
        $this->assertEquals(111, $parsed->id);
        $this->assertEquals(EAPPacket::TYPE_IDENTITY, $parsed->type);
        $this->assertEquals($p->data, $parsed->data);

        $p2 = new EAPPacket();
        $p2->code = EAPPacket::CODE_RESPONSE;
        $p2->id   = 128;
        $p2->type = EAPPacket::TYPE_NOTIFICATION;
        $p2->data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x99\x98\x97\x96\x95\x94\x93\x92\x91\x90";

        $p3 = EAPPacket::fromString($p2->__toString());

        $this->assertEquals(EAPPacket::CODE_RESPONSE, $p3->code);
        $this->assertEquals(128, $p3->id);
        $this->assertEquals(2, $p3->type);
        $this->assertEquals("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x99\x98\x97\x96\x95\x94\x93\x92\x91\x90", $p3->data);
    }

    public function testEapMsChapV2()
    {
        $server = getenv('RADIUS_SERVER_ADDR');
        $user   = getenv('RADIUS_USER');
        $pass   = getenv('RADIUS_PASS');
        $secret = getenv('RADIUS_SECRET');

        if (!$server) {
            $this->markTestSkipped('RADIUS_SERVER_ADDR environment variable not set');
        } elseif (!$user) {
            $this->markTestSkipped('RADIUS_USER environment variable not set');
        } elseif (!$pass) {
            $this->markTestSkipped('RADIUS_PASS environment variable not set');
        } elseif (!$secret) {
            $this->markTestSkipped('RADIUS_SECRET environment variable not set');
        }

        $client = new Radius();
        $client->setServer($server)
               ->setSecret($secret);

        $success = $client->accessRequestEapMsChapV2($user, $pass);

        if (!$success) {
            $reply = $client->getReceivedAttribute('Reply-Message');
            $this->fail(sprintf(
                "Radius access request failed (%d): %s.%s",
                $client->getErrorCode(),
                $client->getErrorMessage(),
                !empty($reply) ? "\nReply-Message: $reply" : ''
            ));
        } else {
            $this->assertTrue($success);
        }
    }

    public function testCoaRequestPacket()
    {
        $expected = hex2bin('2b000047040c9334f368087d6e26edcbdab0dc5201066e656d6f04060a3201192c0f4130313132323333343435353637066925e6b35012791f0c663611ba2f04dd3934458582df');

        $client = new Radius();
        $client->setPacketType(Radius::TYPE_COA_REQUEST)
            ->setUsername('nemo')
            ->setNasIPAddress('10.50.1.25')
            ->setAttribute(44, "A011223344556")  // Acct-Session-Id
            ->setAttribute(55, 1764091571)       // Event-Timestamp
            ->setIncludeMessageAuthenticator(true);

        $packet = $client->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        $this->assertEquals($expected, $packet);

    }

    public function testDisconnectRequestPacket()
    {
        $expected = hex2bin('2801001c1b23624c3543ceba55f1be55a714ca5e01086d6368696261');
        $authenticator = substr($expected, 4, 16);

        $client = new Radius();
        $client->getNextIdentifier();
        $client->setPacketType(Radius::TYPE_DISCONNECT_REQUEST)
            ->setUsername('mchiba')
            ->setSecret('?');

        $packet = $client->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        // Replace the authenticator calculated with the incorrect secret to the one in the example
        $packet = substr($packet, 0, 4) . $authenticator . substr($packet, 20);

        $this->assertEquals($expected, $packet);
    }

    public function testDisconnectRequestPacketWithAcctSessionId()
    {
        $expected = hex2bin('2801001ead0d8e5355b6bd02a0cbace64e3877bd2c0a3930323334353637');
        $authenticator = substr($expected, 4,  16);
        $client = new Radius();
        $client->getNextIdentifier();
        $client->setPacketType(Radius::TYPE_DISCONNECT_REQUEST)
            ->setSecret('?')
            ->setAttribute(44, '90234567');

        $packet = $client->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        // Replace the authenticator calculated with the incorrect secret to the one in the example
        $packet = substr($packet, 0, 4) . $authenticator . substr($packet, 20);

        $this->assertEquals($expected, $packet);
    }

    public function testDisconnectRequestPacketWithFramedIPAddress()
    {
        $expected = hex2bin('2801001a0bda33fe765b05f0fd9cc32a2f6b518208060a000203');
        $authenticator = substr($expected, 4,  16);

        $client = new Radius();
        $client->getNextIdentifier();
        $client->setPacketType(Radius::TYPE_DISCONNECT_REQUEST)
            ->setSecret('?')
            ->setAttribute(8, '10.0.2.3');

        $packet = $client->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        // Replace the authenticator calculated with the incorrect secret to the one in the example
        $packet = substr($packet, 0, 4) . $authenticator . substr($packet, 20);

        $this->assertEquals($expected, $packet);
    }

    public function testAccountingStartPacket()
    {
        $expected = '040000505ef3e51b37c8fea5ecac7f1fb05a5adc3706693225ba2806000000012c0c53455353494f4e5f494406060000000201066e656d6f04060a32011950127c0d915b80767f18e5e2ff16dec138ae';

        $client = new Radius();
        $client->setSecret('xyzzy5461')
            ->setAttribute('Event-Timestamp', 1764894138)
            ->setAttribute('Acct-Status-Type', 1)
            ->setAttribute('Acct-Session-Id', 'SESSION_ID')
            ->setAttribute('Service-Type', 2)
            ->setUsername('nemo')
            ->setNasIPAddress('10.50.1.25')
            ->setIncludeMessageAuthenticator(true);

        $packet = $client->setPacketType(Radius::TYPE_ACCOUNTING_REQUEST)
            ->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        $this->assertEquals($expected, bin2hex($packet));
    }

    public function testAccountingInterimUpdatePacket()
    {
        $expected = '0400006e6bb25cb08253fc2c8555cd6b318bdc783706693225ba2806000000032c0c53455353494f4e5f494406060000000201066e656d6f04060a3201192e060000012c2a06000025262b060000125c2f060000005630060000002f5012b1f2a571c4576972731cc537f683e0a5';

        $client = new Radius();
        $client->setSecret('xyzzy5461')
            ->setAttribute('Event-Timestamp', 1764894138)
            ->setAttribute('Acct-Status-Type', 3)  // Interim-Update
            ->setAttribute('Acct-Session-Id', 'SESSION_ID')
            ->setAttribute('Service-Type', 2)
            ->setUsername('nemo')
            ->setNasIPAddress('10.50.1.25')
            ->setAttribute('Acct-Session-Time', 300)
            ->setAttribute('Acct-Input-Octets', 9510)
            ->setAttribute('Acct-Output-Octets', 4700)
            ->setAttribute('Acct-Input-Packets', 86)
            ->setAttribute('Acct-Output-Packets', 47)
            ->setIncludeMessageAuthenticator(true);

        $packet = $client->setPacketType(Radius::TYPE_ACCOUNTING_REQUEST)
            ->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        $this->assertEquals($expected, bin2hex($packet));
    }

    public function testAccountingStopPacket()
    {
        $expected = '0400006e6ba0589b1c1d5a430aeb88e2d8c040573706693225ba2806000000022c0c53455353494f4e5f494406060000000201066e656d6f04060a3201192e060000020b2a0600002ec02b06000470c02f06000000bb3006000011c350129ef6ddca319a8ae00541d4e151495338';

        $client = new Radius();
        $client->setSecret('xyzzy5461')
            ->setAttribute('Event-Timestamp', 1764894138)
            ->setAttribute('Acct-Status-Type', 2)
            ->setAttribute('Acct-Session-Id', 'SESSION_ID')
            ->setAttribute('Service-Type', 2)
            ->setUsername('nemo')
            ->setNasIPAddress('10.50.1.25')
            ->setAttribute('Acct-Session-Time', 523)
            ->setAttribute('Acct-Input-Octets', 11968)
            ->setAttribute('Acct-Output-Octets', 291008)
            ->setAttribute('Acct-Input-Packets', 187)
            ->setAttribute('Acct-Output-Packets', 4547)
            ->setIncludeMessageAuthenticator(true);

        $packet = $client->setPacketType(Radius::TYPE_ACCOUNTING_REQUEST)
            ->generateRadiusPacket(Radius::AUTH_ACCOUNTING);

        $this->assertEquals($expected, bin2hex($packet));
    }
}
