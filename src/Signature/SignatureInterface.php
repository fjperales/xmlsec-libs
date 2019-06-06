<?php
namespace PacoP\XMLSecLibs\Signature;


use PacoP\XMLSecLibs\CryptoToolKit\CryptoToolKitInterface;

/**
 * Interface SecurityInterface
 * @package PacoP\XMLSecLibs\Signature
 */
interface SignatureInterface
{
    //Signature methods constants
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    //Signer types constants
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    const XADES = 'http://uri.etsi.org/01903/v1.3.2#';

    //Digest methods constants
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    //Canonicalization constants
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public function createSignature(string $xml, CryptoToolKitInterface $cryptoToolKit, string $signatureMethod, string $canonicalMethod , string $digestMethod) :string;
}