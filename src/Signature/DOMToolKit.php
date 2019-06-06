<?php


namespace PacoP\XMLSecLibs\Signature;


class DOMToolKit
{
    public function findNode(\DOMDocument $dom, $namespace, $nodeName)
    {
        if($namespace){
            return $dom->getElementsByTagNameNS($namespace,$nodeName)->item(0);
        }else{
            return $dom->getElementsByTagName($nodeName)->item(0);
        }

    }

    public function addNode(\DOMNode $node, $namespace, $name, $value = null, $attr=array()){
        $doc = $node->ownerDocument;
        if (!is_null($value)) {
            $element = $doc->createElementNS($namespace, $name, $value);
        } else {
            $element = $doc->createElementNS($namespace, $name);
        }
        $node->appendChild($element);

        if($attr){
            $this->addAttribute($element, $attr);
        }

        return $element;
    }

    public function addAttribute(\DOMElement $node, $attribute=array())
    {
        foreach ($attribute as $key=>$value){
            $node->setAttribute($key, $value);
        }
    }

    public function canonicalize(\DOMNode $node, $canonicalmethod, $arXPath = null, $prefixList = null)
    {
        $this->validateCanonicalization($canonicalmethod);

        $exclusive = false;
        $withComments = false;
        switch ($canonicalmethod) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                $exclusive = false;
                $withComments = false;
                break;
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                $withComments = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                $exclusive = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $exclusive = true;
                $withComments = true;
                break;
        }

        return $node->C14N($exclusive, $withComments, $arXPath, $prefixList);
    }

    public function generateGUID($prefix = false)
    {
        $uuid = md5(uniqid(mt_rand(), true));
        if ($prefix) {
            return $prefix . "-" . $uuid;
        }
        return $uuid;

    }

    private function validateCanonicalization($canonicalmethod)
    {
        $canonicalizationMethods = ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
            'http://www.w3.org/2001/10/xml-exc-c14n#',
            'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'];

        if(!in_array($canonicalmethod,$canonicalizationMethods)){
            throw new \Exception("Cannot validate canonicalization method: Unsupported <$canonicalmethod>");
        }

    }
}