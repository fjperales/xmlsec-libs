<?php


namespace PacoP\XMLSecLibs\Signature;


use PacoP\XMLSecLibs\CryptoToolKit\CryptoToolKitInterface;

class XAdESBES extends XMLDsig
{
    const NAMESPACE = SignatureInterface::XADES;

    private $timeZone = 'Europe/Madrid';

    public function setTimeZone($timeZone)
    {
        $this->timeZone = $timeZone;
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

        //Adding Qualifying Properties
        $this->addObjectXades($crypto, $canonicalMethod, $digestMethod);

        //Adding KeyInfo
        $this->addKeyInfo($crypto,$canonicalMethod, $digestMethod);

        //Adding signature
        $this->addSignatureValue($crypto, $canonicalMethod, $signatureMethod);

        //return
        return $this->doc->saveXML();
    }

    /**
     * @param CryptoToolKitInterface $crypto
     * @param $canonicalMethod
     * @param $digestMethod
     */
    protected function addObjectXades(CryptoToolKitInterface $crypto, $canonicalMethod, $digestMethod)
    {
        $nodeSignature = $this->domUtils->findNode($this->doc,XMLDsig::NAMESPACE, "Signature");
        $nodeObject = $this->domUtils->addNode($nodeSignature, XMLDsig::NAMESPACE, 'ds:Object');

        $attributes = [
            'Id' => $this->signatureId."-QualifyingProperties",
            'Target' => '#'.$this->signatureId.'-Signature'
        ];
        $nodeQualifyingProperties = $this->domUtils->addNode($nodeObject, self::NAMESPACE, 'xades:QualifyingProperties', null, $attributes);

        $nodeQualifyingProperties->setAttributeNS('http://www.w3.org/2000/xmlns/' ,'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');

        //Add SignedProperties
        $this->addSignedProperties($crypto, $canonicalMethod, $digestMethod);

    }

    private function addSignedProperties(CryptoToolKitInterface $crypto, $canonicalMethod, $digestMethod)
    {
        $nodeQualifyingProperties = $this->domUtils->findNode($this->doc,self::NAMESPACE,"QualifyingProperties");
        $nodeSignedProperties = $this->domUtils->addNode($nodeQualifyingProperties, self::NAMESPACE, 'xades:SignedProperties',null, ['Id'=>$this->signatureId.'-SignedProperties']);

        //Add SignedSignatureProperties
        $this->addSignedSignatureProperties($crypto, $canonicalMethod, $digestMethod);

        //Add SignedDataObjectProperties
        $this->addSignedDataObjectProperties();

        $attrReference = ['Type'=>'http://uri.etsi.org/01903#SignedProperties',
            'URI'=>'#'.$this->signatureId.'-SignedProperties'];
        $this->addReference($nodeSignedProperties,$crypto, $canonicalMethod ,$digestMethod, $attrReference);
    }

    private function addSignedSignatureProperties(CryptoToolKitInterface $crypto, $canonicalMethod, $digestMethod)
    {
        $nodeSignedProperties = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedProperties");
        $nodeSignedSignatureProperties = $this->domUtils->addNode($nodeSignedProperties, self::NAMESPACE, 'xades:SignedSignatureProperties');

        //SigningTime
        try{
            //$signingTimeObj = new \DateTime("now", new \DateTimeZone($this->timeZone));
            //$signingTime = $signingTimeObj->format('Y-m-d\TH:i:sP');
            $signingTime = "2019-05-28T17:48:53+02:00";
        }catch (\Exception $e){
            throw new \Exception("Unknown or bad timezone <$this->timeZone>");
        }
        $this->domUtils->addNode($nodeSignedSignatureProperties, self::NAMESPACE, 'xades:SigningTime',$signingTime);

        //SigningCertificate B-LEVEL
        $nodeSigningCertificate = $this->domUtils->addNode($nodeSignedSignatureProperties, self::NAMESPACE, 'xades:SigningCertificate');

        //Cert
        $nodeCert = $this->domUtils->addNode($nodeSigningCertificate, self::NAMESPACE, 'xades:Cert');

        //CertDigest
        $nodeCertDigest = $this->domUtils->addNode($nodeCert, self::NAMESPACE, 'xades:CertDigest');
        $this->domUtils->addNode($nodeCertDigest, XMLDsig::NAMESPACE, 'ds:DigestMethod', null, ['Algorithm'=>$digestMethod]);
        $this->domUtils->addNode($nodeCertDigest, XMLDsig::NAMESPACE, 'ds:DigestValue', $crypto->digestX509($digestMethod));

        //IssuerSerial
        $nodeIssuerSerial = $this->domUtils->addNode($nodeCert, self::NAMESPACE, 'xades:IssuerSerial');
        $this->domUtils->addNode($nodeIssuerSerial, XMLDsig::NAMESPACE, 'ds:X509IssuerName', $crypto->getIssuerName());
        //$this->domUtils->addNode($nodeIssuerSerial, XMLDsig::NAMESPACE, 'ds:X509IssuerName', "CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES");
        $this->domUtils->addNode($nodeIssuerSerial, XMLDsig::NAMESPACE, 'ds:X509SerialNumber', $crypto->getSerialNumber());


    }

    private function addSignedDataObjectProperties()
    {
        $nodeSignedProperties = $this->domUtils->findNode($this->doc,self::NAMESPACE,"SignedProperties");
        $nodeSignedDataObjectProperties = $this->domUtils->addNode($nodeSignedProperties, self::NAMESPACE, 'xades:SignedDataObjectProperties');

        //DataObjectFormat
        $nodeDataObjectFormat = $this->domUtils->addNode($nodeSignedDataObjectProperties, self::NAMESPACE, 'xades:DataObjectFormat',null,['ObjectReference'=>'#'.$this->signatureReferenceId]);
        $this->domUtils->addNode($nodeDataObjectFormat, self::NAMESPACE, 'xades:Description');

        //ObjectIdentifier
        $nodeObjectIdentifier = $this->domUtils->addNode($nodeDataObjectFormat, self::NAMESPACE, 'xades:ObjectIdentifier');
        $this->domUtils->addNode($nodeObjectIdentifier, self::NAMESPACE, 'xades:Identifier','urn:oid:1.2.840.10003.5.109.10',['Qualifier'=>'OIDAsURN']);
        $this->domUtils->addNode($nodeObjectIdentifier, self::NAMESPACE, 'xades:Description');
        $this->domUtils->addNode($nodeDataObjectFormat, self::NAMESPACE, 'xades:MimeType','text/xml');
        $this->domUtils->addNode($nodeDataObjectFormat, self::NAMESPACE, 'xades:Encoding');

    }

}