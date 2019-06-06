<?php
namespace PacoP\XMLSecLibs;

use PacoP\XMLSecLibs\CryptoToolKit\CryptoToolKitInterface;
use PacoP\XMLSecLibs\Signature\SignatureInterface;
use PacoP\XMLSecLibs\Signature\XAdESBES;
use PacoP\XMLSecLibs\Signature\XMLDsig;

class XMLSecLibs
{
    protected $canonicalMethod = SignatureInterface::C14N;

    protected $digestMethod = SignatureInterface::SHA256;

    protected $signatureMethod = SignatureInterface::RSA_SHA256;

    public function sign($xml, $type,CryptoToolKitInterface $crypto, $options=array())
    {
        switch ($type){
            case SignatureInterface::XMLDSIGNS:
                $signature = new XMLDsig();
                break;
            case SignatureInterface::XADES:
                $signature = new XAdESBES();
                if(isset($options['timezone'])){
                    $signature->setTimeZone($options['timezone']);
                }
                break;
            default:
                throw new \Exception("Unsupported signature type <$type>");
        }
        return $signature->createSignature($xml, $crypto, $this->signatureMethod, $this->canonicalMethod, $this->digestMethod);
    }

    public function setCanonicalMethod($method)
    {
        $this->canonicalMethod = $method;
    }

    public function setDigestMethod($method)
    {
        $this->digestMethod = $method;
    }

    public function setSignatureMethod($method)
    {
        $this->signatureMethod = $method;
    }

}