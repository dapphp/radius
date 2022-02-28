<?php

namespace Dapphp\Radius;

/**
 * Class for EAP packets encapsulated in RADIUS packets
 *
 */
class EAPPacket
{
    const CODE_REQUEST  = 1;
    const CODE_RESPONSE = 2;
    const CODE_SUCCESS  = 3;
    const CODE_FAILURE  = 4;

    const TYPE_IDENTITY      = 1;
    const TYPE_NOTIFICATION  = 2;
    const TYPE_NAK           = 3;
    const TYPE_MD5_CHALLENGE = 4;
    const TYPE_OTP           = 5;
    const TYPE_GENERIC_TOKEN = 6;
    const TYPE_PEAP_EAP      = 25;
    const TYPE_EAP_MS_AUTH   = 26;

    public $code;
    public $id;
    public $type;
    public $data;
    
    /**
     * Helper function to generate an EAP Identity packet
     *
     * @param  string  $identity  The identity (username) to send in the packet
     * @param  int  $id  The packet ID (random if omitted)
     * @return string An EAP identity packet
     * @throws \Exception
     */
    public static function identity($identity, $id = null)
    {
        $packet = new self();
        $packet->setId($id);
        $packet->code = self::CODE_RESPONSE;
        $packet->type = self::TYPE_IDENTITY;
        $packet->data = $identity;

        return (string) $packet;
    }
    
    /**
     * Helper function to generate an EAP Legacy NAK packet
     *
     * @param  string  $desiredAuth  The desired auth method
     * @param  int  $id  The packet ID, given by server at predecessing proposal
     * @return string An EAP Legacy NAK packet
     * @throws \Exception
     */
    public static function legacyNak($desiredAuth, $id)
    {
        $packet = new self();
        $packet->setId($id);
        $packet->code = self::CODE_RESPONSE;
        $packet->type = self::TYPE_NAK;
        $packet->data = chr($desiredAuth);

        return (string) $packet;
    }
    
    /**
     * Helper function to generate an EAP Success packet
     *
     * @param  int  $id  The packet ID, given by server at predecessing proposal
     * @return string An EAP Legacy NAK packet
     * @throws \Exception
     */
    public static function eapSuccess($id)
    {
		$eapSuccess = new MsChapV2Packet();
		$eapSuccess->opcode = MsChapV2Packet::OPCODE_SUCCESS;
    
        return self::mschapv2($eapSuccess, $id);
    }
    
    /**
     * Helper function for sending an MS-CHAP-V2 packet encapsulated in an EAP packet
     *
     * @param  \Dapphp\Radius\MsChapV2Packet  $chapPacket  The MSCHAP v2 packet to send
     * @param  int  $id  The CHAP packet identifier (random if omitted)
     * @return string An EAP packet with embedded MS-CHAP-V2 packet in the data field
     * @throws \Exception
     */
    public static function mschapv2(\Dapphp\Radius\MsChapV2Packet $chapPacket, $id = null)
    {
        $packet = new self();
        $packet->setId($id);
        $packet->code = self::CODE_RESPONSE;
        $packet->type = self::TYPE_EAP_MS_AUTH;
        $packet->data = (string) $chapPacket;

        return (string) $packet;
    }

    /**
     * Convert a raw EAP packet into a structure
     *
     * @param string $packet The EAP packet
     * @return \Dapphp\Radius\EAPPacket|bool  The parsed packet structure
     */
    public static function fromString($packet)
    {
        // TODO: validate incoming packet better

        $p = new self();
        $p->code = ord($packet[0]);
        $p->id   = ord($packet[1]);
        $temp    = unpack('n', substr($packet, 2, 2));
        $length  = array_shift($temp);

        if (strlen($packet) != $length) {
            return false;
        }

        $p->type = ord($packet[4]);
        $p->data = substr($packet, 5);

        return $p;
    }
    
    /**
     * Set the ID of the EAP packet
     *
     * @param  int  $id  The EAP packet ID
     * @return \Dapphp\Radius\EAPPacket Fluent interface
     * @throws \Exception
     */
    public function setId($id = null)
    {
        if (is_null($id)) {
            $this->id = random_int(0, 255);
        } else {
            $this->id = (int) $id;
        }

        return $this;
    }

    /**
     * Convert the packet to a raw byte string
     *
     * @return string The packet as a byte string for sending over the wire
     */
    public function __toString()
    {
        return chr($this->code) .
               chr($this->id) .
               pack('n', 5 + strlen($this->data)) .
               chr($this->type) .
               $this->data;
    }
}
