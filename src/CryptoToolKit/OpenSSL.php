<?php
namespace PacoP\XMLSecLibs\CryptoToolKit;

use PacoP\XMLSecLibs\Signature\SignatureInterface;

/**
 * Class OpenSSL
 * @package PacoP\XMLSecLibs\CryptoToolKit
 */
class OpenSSL implements CryptoToolKitInterface
{
    /**
     * @var bool|resource
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $publicKey;

    /**
     * @var string
     */
    protected $modulus;

    /**
     * @var string
     */
    protected $exponent;

    /** @var string */
    protected $issuerName;

    /** @var string */
    protected $serialNumber;

    /** @var string */
    protected $x509Reader;


    /**
     * OpenSSL constructor.
     * @param $privKeyPath
     * @param $publicKeyPath
     * @param $passphrase
     * @throws \Exception
     */
    public function __construct($privKeyPath, $passphrase, $type="PEM")
    {
        $privKey = file_get_contents($privKeyPath);
        switch ($type){
            case "PEM":
                $this->x509Reader = openssl_x509_read(file_get_contents($privKeyPath));
                $this->parsePEM($privKey, $passphrase);
                break;
            case "PKCS12":
                //$this->parsePKCS12($privKey, $passphrase);
                break;
        }
    }

    private function parsePKCS12($privKey, $passphrase)
    {
        if (openssl_pkcs12_read($privKey, $infoCert, $passphrase)) {
            $this->x509Reader = openssl_x509_read($infoCert['cert']);
            $this->parsePEM($infoCert['pkey'],$passphrase);
        } else {
            throw new \Exception("Unable to read the cert store");
        }
    }

    private function parsePEM($privKey, $passphrase)
    {
        if(!$this->privateKey = openssl_get_privatekey($privKey, $passphrase)){
            throw new \Exception("Cannot open private key PEM file");
        }


        $x509 = openssl_x509_parse($this->x509Reader);

        $this->serialNumber = $x509['serialNumber'];
        foreach ($x509['issuer'] as $key=>$value){
            if($this->issuerName){
                $this->issuerName.=", $key=$value";
            }else{
                $this->issuerName.="$key=$value";
            }

        }

        $pubRsaKey = openssl_pkey_get_public($privKey);
        $keyData = openssl_pkey_get_details($pubRsaKey);

        $this->publicKey = $this->cleanPEM($keyData['key']);
        openssl_x509_export($this->x509Reader,$this->publicKey);
        $this->publicKey= $this->cleanPEM($this->publicKey);

        if($keyData['type'] == OPENSSL_KEYTYPE_RSA){
            //MODULUS
            $this->modulus = base64_encode($keyData['rsa']['n']);
            //EXPONENT
            $this->exponent = base64_encode($keyData['rsa']['e']);
        }
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function getModulus(): string
    {
        return $this->modulus;
    }

    /**
     * @return string
     */
    public function getExponent(): string
    {
        return $this->exponent;
    }

    /**
     * @return string
     */
    public function getIssuerName(): string
    {
        return $this->issuerName;
    }

    /**
     * @return string
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }

    /**
     * @param string $alg
     * @return string
     * @throws \Exception
     */
    public function digestX509(string $alg): string
    {
        $alg = $this->validateDigestMethod($alg);
        return base64_encode(openssl_x509_fingerprint($this->x509Reader,$alg,true));
    }


    /**
     * @param string $data
     * @param string $alg
     * @return string
     * @throws \Exception
     */
    public function sign(string $data, string $alg): string
    {
        $alg = $this->validateSignatureMethod($alg);
        if(!openssl_sign($data, $signature, $this->privateKey, $alg)){
            throw new \Exception("An error occurred signing document");
        }
        return base64_encode($signature);
    }


    /**
     * @param $data
     * @param $alg
     * @return string
     * @throws \Exception
     */
    public function digest(string $data, string $alg): string
    {
        $alg = $this->validateDigestMethod($alg);
        return base64_encode(hash($alg, $data, true));
    }


    /**
     * @param string $data
     * @param string $signature
     * @param string $publicKeyPath
     * @param $alg
     * @return bool
     * @throws \Exception
     */
    public function verify(string $data, string $signature, string $publicKeyPath, $alg): bool
    {
        $alg = $this->validateSignatureMethod($alg);
        $ok = openssl_verify($data, $signature, $this->publicKey, $alg);
        if ($ok == 1) {
            return true;
        } elseif ($ok == 0) {
            return false;
        } else {
            throw new \Exception(openssl_error_string());;
        }
    }

    /**
     * @param $alg
     * @return int
     * @throws \Exception
     */
    private function validateSignatureMethod($alg)
    {
        switch ($alg) {
            case SignatureInterface::RSA_SHA1:
                $alg = OPENSSL_ALGO_SHA1;
                break;
            case SignatureInterface::RSA_SHA256:
                $alg = OPENSSL_ALGO_SHA256;
                break;
            case SignatureInterface::RSA_SHA384:
                $alg = OPENSSL_ALGO_SHA384;
                break;
            case SignatureInterface::RSA_SHA512:
                $alg = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new \Exception("Cannot verify signature method: Unsupported Algorithm <$alg>");
        }
        return $alg;
    }

    /**
     * @param $alg
     * @return string
     * @throws \Exception
     */
    private function validateDigestMethod($alg)
    {
        switch ($alg) {
            case SignatureInterface::SHA1:
                $alg = 'sha1';
                break;
            case SignatureInterface::SHA256:
                $alg = 'sha256';
                break;
            case SignatureInterface::SHA384:
                $alg = 'sha384';
                break;
            case SignatureInterface::SHA512:
                $alg = 'sha512';
                break;
            default:
                throw new \Exception("Cannot validate digest: Unsupported Algorithm <$alg>");
        }
        return $alg;
    }

    /**
     * @param string $pem
     * @return string
     */
    private function cleanPEM(string $pem)
    {
        $pem = str_replace("-----BEGIN CERTIFICATE-----","",$pem);
        $pem = str_replace("\n","",$pem);
        $pem = str_replace("\r","",$pem);
        $pem = str_replace("-----END CERTIFICATE-----","",$pem);
        return trim($pem);
    }

    private function formatPEM($pem, $addBegin=true)
    {
        $newPEM = wordwrap(str_replace([
            "\n",
            "\r"
        ], "", trim($pem)), 64, "\r\n", true);
        if($addBegin){
            return "-----BEGIN CERTIFICATE-----\n" . $newPEM . "\n-----END CERTIFICATE-----";
        }
        return $newPEM;
    }
}