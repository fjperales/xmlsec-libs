<?php

include '../vendor/autoload.php';

use PacoP\XMLSecLibs\XMLSecLibs;
use PacoP\XMLSecLibs\CryptoToolKit\OpenSSL;

$xml = file_get_contents('simple.xml');
$type = 'http://uri.etsi.org/01903/v1.3.2#';
$privKeyPath = 'certs/cert.key';
//$privKeyPath = 'certs/cert.p12';
$passphrase = '12345';

//$crypto = new OpenSSL($privKeyPath, $passphrase, "PKCS12");
$crypto = new OpenSSL($privKeyPath, $passphrase);

$xmlsec = new XMLSecLibs();
try {
    $options = ['timezone' => 'Europe/Madrid'];
    $xmlsec->setDigestMethod('http://www.w3.org/2001/04/xmlenc#sha512');
    $xmlsec->setSignatureMethod('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    $signature = $xmlsec->sign($xml, $type, $crypto, $options);
} catch (\Exception $e) {
    echo "ERROR: " . $e->getMessage();
    die();
}

echo $signature;
file_put_contents("simple.xadesbes.xml", $signature);
exec("AutoFirma verify -i simple.xadesbes.xml");