<?php


namespace PacoP\XMLSecLibs\Signature;


use PacoP\XMLSecLibs\CryptoToolKit\CryptoToolKitInterface;

class XMLDsig implements SignatureInterface
{
    const NAMESPACE = SignatureInterface::XMLDSIGNS;

    /** @var \DOMDocument */
    protected $doc;

    /** @var DOMToolKit */
    protected $domUtils;

    /** @var string */
    protected $pacoId;

    /** @var string */
    protected $contentId;

    /** @var string */
    protected $signatureId;

    /** @var string */
    protected $signatureReferenceId;

    public function __construct()
    {
        $this->doc = new \DOMDocument();
        $this->domUtils = new DOMToolKit();
    }

    public function createSignature(
        string $xml,
        CryptoToolKitInterface $crypto,
        string $signatureMethod,
        string $canonicalMethod,
        string $digestMethod
    ): string {

        //Creation Envelop
        $this->initEnvelopNode($xml);

        //Creation signature node
        $this->initSignatureEnvelop();

        //Setting canonical and signature methods
        $this->addCanonicalizationMethod($canonicalMethod);
        $this->addSignatureMethod($signatureMethod);

        //Adding reference of document
        $this->addSignatureReference($crypto, $canonicalMethod, $digestMethod);

        //Adding KeyInfo
        $this->addKeyInfo($crypto,$canonicalMethod, $digestMethod);

        //Adding signature
        $this->addSignatureValue($crypto, $canonicalMethod, $signatureMethod);

        //return
        return $this->doc->saveXML();
    }

    protected function addCanonicalizationMethod($canonicalMethod)
    {
        $node = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedInfo");
        $this->domUtils->addNode($node, self::NAMESPACE, 'ds:CanonicalizationMethod',null,['Algorithm'=>$canonicalMethod]);
    }

    protected function addSignatureMethod($signatureMethod)
    {
        $node = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedInfo");
        $this->domUtils->addNode($node, self::NAMESPACE, 'ds:SignatureMethod',null, ['Algorithm'=>$signatureMethod]);
    }

    protected function addSignatureReference(CryptoToolKitInterface $crypto, $canonicalMethod, $digestMethod)
    {
        $node = $this->doc->getElementsByTagName("CONTENT");
        $this->signatureReferenceId = $this->domUtils->generateGUID("Reference");
        $attrReference = [
            'Id' => $this->signatureReferenceId,
            'Type' => 'http://www.w3.org/2000/09/xmldsig#Object',
            'URI' => '#'.$this->contentId
        ];
        $transforms = ['Algorithm' => $canonicalMethod];
        $this->addReference($node->item(0),$crypto, $canonicalMethod ,$digestMethod, $attrReference, $transforms);
    }

    protected function addKeyInfo(CryptoToolKitInterface $crypto,$canonicalMethod, $digestMethod)
    {
        $publicKey = $crypto->getPublicKey();
        $modulus = $crypto->getModulus();
        $exponent = $crypto->getExponent();
        $nodeKeyInfo = $this->doc->getElementsByTagNameNS(self::NAMESPACE,"KeyInfo")->item(0);

        //Public Key
        $nodeX509Data = $this->domUtils->addNode($nodeKeyInfo, self::NAMESPACE, 'ds:X509Data');
        $nodeX509Certificate = $this->domUtils->addNode($nodeX509Data, self::NAMESPACE, 'ds:X509Certificate', $publicKey);

        //Modulus y Exponent
        $nodeKeyValue = $this->domUtils->addNode($nodeKeyInfo, self::NAMESPACE, 'ds:KeyValue');
        $nodeRSAKeyValue = $this->domUtils->addNode($nodeKeyValue, self::NAMESPACE, 'ds:RSAKeyValue');
        $nodeModulus = $this->domUtils->addNode($nodeRSAKeyValue, self::NAMESPACE, 'ds:Modulus', $modulus);
        $nodeExponent = $this->domUtils->addNode($nodeRSAKeyValue, self::NAMESPACE, 'ds:Exponent', $exponent);

        $attrReference = [
            'URI' => '#'.$this->signatureId."-KeyInfo"
        ];
        $this->addReference($nodeKeyInfo,$crypto, $canonicalMethod ,$digestMethod, $attrReference);

    }

    protected function addSignatureValue(CryptoToolKitInterface $crypto,$canonicalMethod, $signatureMethod)
    {
        $nodeSignedInfo = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedInfo");

        $data = $this->domUtils->canonicalize($nodeSignedInfo,$canonicalMethod);
        $signatureValue = $crypto->sign($data,$signatureMethod);

        $nodeSignatureValue = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignatureValue");
        $nodeSignatureValue->nodeValue = $signatureValue;

    }

    protected function addReference($node,CryptoToolKitInterface $crypto, $canonicalMethod, $digestMethod, $attrReference=array(), $tranform=array())
    {
        $nodeSignedInfo = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedInfo");
        $nodeReference = $this->domUtils->addNode($nodeSignedInfo, self::NAMESPACE, 'ds:Reference',null,$attrReference);

        if($tranform){
            $nodeTransforms = $this->domUtils->addNode($nodeReference, self::NAMESPACE, 'ds:Transforms');
            foreach ($tranform as $key=>$value){
                $this->domUtils->addNode($nodeTransforms, self::NAMESPACE, 'ds:Transform',null,[$key=> $value]);
            }
        }

        $this->domUtils->addNode($nodeReference, self::NAMESPACE, 'ds:DigestMethod',null,["Algorithm"=> $digestMethod]);

        $data = $this->domUtils->canonicalize($node, $canonicalMethod);
        $digestValue = $crypto->digest($data,$digestMethod);
        $this->domUtils->addNode($nodeReference, self::NAMESPACE,'ds:DigestValue',$digestValue);

    }

    protected function initEnvelopNode($xml)
    {
        $content = new \DOMDocument();
        $content->loadXML($xml);

        $this->doc = new \DOMDocument();
        $this->doc->loadXML('<PACOP><CONTENT></CONTENT></PACOP>');

        $nodeContent = $this->domUtils->findNode($this->doc,null,"CONTENT");
        $node = $nodeContent->ownerDocument->importNode($content->documentElement, true);
        $nodeContent->appendChild($node);

        $this->pacoId = $this->domUtils->generateGUID("PACOP");
        $nodePacop = $this->domUtils->findNode($this->doc,null,"PACOP");
        $this->domUtils->addAttribute($nodePacop, ['Id' => $this->pacoId]);

        $this->contentId = $this->domUtils->generateGUID("CONTENT");
        $nodeContent = $this->domUtils->findNode($this->doc,null,"CONTENT");
        $this->domUtils->addAttribute($nodeContent, ['Id' => $this->contentId]);
        $this->domUtils->addAttribute($nodeContent, ['MimeType' => 'text/xml']);

        return $this->doc;
    }

    protected function initSignatureEnvelop()
    {
        $this->signatureId = $this->domUtils->generateGUID("Signature");

        $nodeRoot = $this->domUtils->findNode($this->doc, null,"PACOP");
        $nodeSignature = $this->domUtils->addNode($nodeRoot, self::NAMESPACE, 'ds:Signature', null, ['Id' => $this->signatureId . "-Signature"]);

        $this->domUtils->addNode($nodeSignature, self::NAMESPACE, 'ds:SignedInfo',null, ['Id' => $this->signatureId . "-SignedInfo"]);
        $this->domUtils->addNode($nodeSignature, self::NAMESPACE, 'ds:SignatureValue',null,['Id' => $this->signatureId . "-SignatureValue"]);
        $this->domUtils->addNode($nodeSignature, self::NAMESPACE, 'ds:KeyInfo',null,['Id' => $this->signatureId . "-KeyInfo"]);

    }


}