<?php
namespace PacoP\XMLSecLibs\CryptoToolKit;

/**
 * Interface CryptoToolKitInterface
 * @package PacoP\XMLSecLibs\CryptoToolKit
 */
interface CryptoToolKitInterface
{

    /**
     * @return string
     */
    public function getPublicKey() :string;

    /**
     * @return string
     */
    public function getModulus() :string;

    /**
     * @return string
     */
    public function getExponent() :string;

    /**
     * @param string $data
     * @param string $alg
     * @return string
     */
    public function sign(string $data, string $alg) :string;

    /**
     * @param string $data
     * @param string $alg
     * @return string
     */
    public function digest(string $data, string $alg) :string;


    /**
     * @param string $data
     * @param string $signature
     * @param string $publicKeyPath
     * @param string $alg
     * @return bool
     */
    public function verify(string $data, string $signature, string $publicKeyPath, string $alg) :bool ;

    /**
     * @return string
     */
    public function getIssuerName(): string;

    /**
     * @return string
     */
    public function getSerialNumber(): string;

    /**
     * @return string
     */
    public function digestX509(string $alg): string;


    //public function encrypt();
    //public function decrypt();

}