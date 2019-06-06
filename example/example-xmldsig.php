<?php

include '../vendor/autoload.php';

use PacoP\XMLSecLibs\XMLSecLibs;
use PacoP\XMLSecLibs\CryptoToolKit\OpenSSL;

$xml = file_get_contents('simple.xml');
$type = 'http://www.w3.org/2000/09/xmldsig#';
$privKeyPath = 'certs/micertificado4.key';
$publicKeyPath = 'certs/micertificado4.pem';
$passphrase = 'Mcetpm123';

$crypto = new OpenSSL($privKeyPath,$publicKeyPath, $passphrase);

$xmlsec = new XMLSecLibs();
try{
    $signature = $xmlsec->sign($xml, $type, $crypto);
}catch (\Exception $e){
    echo "ERROR: ".$e->getMessage();
    die();
}

echo $signature;
file_put_contents("simple.xmldsig.xml",$signature);
exec("AutoFirma verify -i simple.xmldsig.xml");