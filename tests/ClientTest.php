<?php

use Dapphp\Radius\Radius;

class ClientTest extends PHPUnit_Framework_TestCase
{
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

    public function testAuthenticationPacket()
    {
        $user    = 'nemo';
        $pass    = 'arctangent';
        $secret  = 'xyzzy5461';
        $nas     = '192.168.1.16';
        $nasPort = 3;

        $client   = new Radius();

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
               ->setRequestId($reqId)
               ->setRequestAuthenticator($reqAuth)
               ->setSecret($secret)
               ->setUsername($user)
               ->setNasIPAddress($nas)
               ->setNasPort($nasPort)
               ->setAttribute(80, str_repeat("\x00", 16))
               ->setMsChapPassword($pass, $challenge);

        $packet = $client->generateRadiusPacket();

        $packet   = bin2hex($packet);
        $expected = "01870082093e4ad125399f8ac4ba6b00ab69a04001066e656d6f04067f000001050600000014501248a3704ac91e8191497a1f3f213eb3381a10000001370b0a740c7921e45e91391a3a00000137013400010000000000000000000000000000000000000000000000004521bd46aebfd2ab3ec21dd6e6bbfa2e4ff325eab720fe37";

        $this->assertEquals($expected, $packet);
    }
}
