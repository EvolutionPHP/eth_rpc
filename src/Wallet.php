<?php
/**
 * @package EvolutionScript
 * @author: EvolutionScript S.A.C.
 * @Copyright (c) 2010 - 2020, EvolutionScript.com
 * @link http://www.evolutionscript.com
 */

namespace aMendoza\Eth_rpc;


use BCMathExtended\BC;
use Elliptic\EC;
use kornrunner\Ethereum\Transaction;
use kornrunner\Keccak;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;

class Wallet
{
	private $secp256k1;
	private $url;
	private $chain_id;
	private $client;
	private $json_version = '2.0';
	/**
	 * SHA3_NULL_HASH
	 *
	 * @const string
	 */
	const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

	public function __construct()
	{
		$this->secp256k1 = new EC('secp256k1');
	}
	/**
	 * isHex
	 *
	 * @param string $value
	 * @return bool
	 */
	private function isHex(string $value)
	{
		return (is_string($value) && preg_match('/^(0x)?[a-fA-F0-9]+$/', $value) === 1);
	}
	/**
	 * isZeroPrefixed
	 *
	 * @param string $value
	 * @return bool
	 */
	private function isZeroPrefixed(string $value)
	{
		return (strpos($value, '0x') === 0);
	}
	/**
	 * stripZero
	 *
	 * @param string $value
	 * @return string
	 */
	private function stripZero(string $value)
	{
		if ($this->isZeroPrefixed($value)) {
			$count = 1;
			return str_replace('0x', '', $value, $count);
		}
		return $value;
	}

	/**
	 * sha3
	 * keccak256
	 *
	 * @param string $value
	 * @return string
	 */
	private function sha3(string $value)
	{
		$hash = Keccak::hash($value, 256);

		if ($hash === $this::SHA3_NULL_HASH) {
			return null;
		}
		return $hash;
	}

	private function privateKeyToPublicKey(string $privateKey)
	{
		if ($this->isHex($privateKey) === false) {
			throw new \Exception('Invalid private key format.');
		}
		$privateKey = $this->stripZero($privateKey);

		if (strlen($privateKey) !== 64) {
			throw new \Exception('Invalid private key length.');
		}
		$privateKey = $this->secp256k1->keyFromPrivate($privateKey, 'hex');
		$publicKey = $privateKey->getPublic(false, 'hex');

		return '0x' . $publicKey;
	}

	/**
	 * publicKeyToAddress
	 *
	 * @param string $publicKey
	 * @return string
	 */
	private function publicKeyToAddress(string $publicKey)
	{
		if ($this->isHex($publicKey) === false) {
			throw new \Exception('Invalid public key format.');
		}
		$publicKey = $this->stripZero($publicKey);

		if (strlen($publicKey) !== 130) {
			throw new \Exception('Invalid public key length.');
		}
		return '0x' . substr($this->sha3(substr(hex2bin($publicKey), 1)), 24);
	}

	public function privateKeyToAddress(string $privateKey)
	{
		return $this->publicKeyToAddress($this->privateKeyToPublicKey($privateKey));
	}
	/*
	 * Create Wallet
	 */
	public function createWallet()
	{
		$config = [
			'private_key_type' => OPENSSL_KEYTYPE_EC,
			'curve_name' => 'secp256k1'
		];
		//Generate private key
		$res = openssl_pkey_new($config);
		if(!$res){
			throw new \Exception('Fail to generate private key. -> ' . openssl_error_string());
		}
		openssl_pkey_export($res, $priv_key);
		//Get public key
		$priv_pem = PEM::fromString($priv_key);

		// Convert to Elliptic Curve Private Key Format
		$ec_priv_key = ECPrivateKey::fromPEM($priv_pem);
		// Then convert it to ASN1 Structure
		$ec_priv_seq = $ec_priv_key->toASN1();

		// Private Key & Public Key in HEX
		$priv_key_hex = bin2hex($ec_priv_seq->at(1)->asOctetString()->string());
		return [
			'address' => $this->privateKeyToAddress($priv_key_hex),
			'private_key' => $priv_key_hex,
		];
	}

	public function dec2hex($var, $prefix=true)
	{
		$data = BC::dechex($var);
		if($prefix){
			return '0x'.$data;
		}else{
			return $data;
		}

	}
	public function hex2dec($var){
		return BC::hexdec($var);
	}
	public function wei2eth($wei)
	{
		return bcdiv($wei,'1000000000000000000',18);
	}
	public function wei2gwei($wei)
	{
		return bcdiv($wei,'1000000000');
	}
	public function eth2wei($eth)
	{
		return bcmul($eth, '1000000000000000000', 0);
	}
	public function gwei2wei($gwei)
	{
		return bcmul($gwei, '1000000000', 0);
	}

	public function rpc_url($url, $chain_id=1)
	{
		if($url == '' || !filter_var($url, FILTER_VALIDATE_URL)){
			throw new \Exception('RPC URL is not defined.');
		}
		$this->url = $url;
		$this->chain_id = $chain_id;
	}
	public function getBalance($account)
	{
		return $this->rpc('eth_getBalance', [$account,'latest'], 1);
	}
	public function blockNumber()
	{
		return $this->rpc('eth_blockNumber', [], 83);
	}
	public function gasPrice()
	{
		return $this->rpc('eth_gasPrice', [], 73);
	}
	public function getTransactionByHash($hash)
	{
		return $this->rpc('eth_getTransactionByHash', [$hash], 1);
	}
	public function getTransactionCount($account)
	{
		return $this->rpc('eth_getTransactionCount', [$account, 'latest'], 1);
	}
	public function createTransaction($from, $to, $value, $private_key, $nonce='', $gasPrice='', $gasLimit='21000')
	{

		$value = $this->dec2hex($this->eth2wei($value));
		if($gasPrice == ''){
			$gasPrice = $this->gasPrice();
		}
		$gasPrice = $this->dec2hex($this->gwei2wei($gasPrice));

		$gasLimit = $this->dec2hex($gasLimit);
		if($nonce == ''){
			$nonce = $this->getTransactionCount($from);
		}
		$transaction = new Transaction($this->dec2hex($nonce), $gasPrice, $gasLimit, $to, $value);

		return $transaction->getRaw($private_key, $this->chain_id);
	}
	public function sendTransaction($raw)
	{
		return $this->rpc('eth_sendRawTransaction',['0x'.$raw]);
	}

	private function rpc($method, $params=[], $id=1)
	{
		if(!$this->url){
			throw new \Exception('RPC URL is not defined.');
		}
		if(!$this->client){
			$this->client = new \GuzzleHttp\Client();
		}
		try {
			$resp = $this->client->post($this->url, [
				'json' => [
					'jsonrpc' => $this->json_version,
					'method' => $method,
					'params' => $params,
					'id' => $id
				]
			]);
			if($resp->getStatusCode() != 200){
				return null;
			}
			$result = json_decode($resp->getBody());
			if(isset($result->error)){
				throw new \Exception($result->error->message);
			}
			if($method == 'eth_getTransactionByHash'){
				$result->result->blockHash = BC::hexdec($result->result->blockHash);
				$result->result->blockNumber = BC::hexdec($result->result->blockNumber);
				$result->result->gas = BC::hexdec($result->result->gas);
				$result->result->gasPrice = $this->wei2eth(BC::hexdec($result->result->gasPrice));
				$result->result->nonce = BC::hexdec($result->result->nonce);
				$result->result->transactionIndex = BC::hexdec($result->result->transactionIndex);
				$result->result->value = $this->wei2eth(BC::hexdec($result->result->value));
				$result->result->type = BC::hexdec($result->result->type);
				$result->result->v = BC::hexdec($result->result->v);
				$result->result->r = BC::hexdec($result->result->r);
				$result->result->s = BC::hexdec($result->result->s);
				return $result->result;
			}elseif ($method == 'eth_getBalance') {
				$wei = BC::hexdec($result->result);
				return $this->wei2eth($wei);
			}elseif ($method == 'eth_sendRawTransaction') {
				return $result->result;
			}elseif ($method == 'eth_gasPrice'){
				$wei = BC::hexdec($result->result);
				return $this->wei2gwei($wei);
			}else{
				$wei = BC::hexdec($result->result);
				return $wei;
			}
		}catch (\Exception $e){
			throw new \Exception($e->getMessage());
		}
	}

}