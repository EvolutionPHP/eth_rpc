# Ethereum account and JSON-RPC client

Create Ethereum wallet and/or connect to JSON-RPC Endpoint from Ethereum or compatibles like BSC

This library requires the [bcmath](http://php.net/manual/en/book.bc.php) PHP extension.

**Installation:**

```bash
composer require amendozadev/eth_rpc
```


**Usage:**

```php
$wallet = new \aMendoza\Eth_rpc\Wallet();

//Create new wallet
$account = $wallet->createWallet(); //['address' => '0xf1b4d0755ef13025c8b1b398237652b7c3ea8dc0', 'private_key' => '81011e578366208ab232d726cb910d1dffd132c84659cede2bfc6b5d0404d234'] 
		
//Connect to RPC URL (URL : Chain ID)
$wallet->rpc_url('https://ropsten.infura.io/v3/', 3);

// get gas price in wei
$wei = $wallet->gasPrice();
echo $wei; // "5000000000"

// convert to eth:
$eth = $wallet->wei2eth($wei);
echo $eth; // "0.000000005000000000"

// block number
$block = $wallet->blockNumber();
echo $block; //18143442

// account balance
$balance = $wallet->getBalance($account['address']);

//Send Transaction
try {
    $to = '0xa48e2ff1e6e4ef5952c64dc505d6983a92d320f7';
    $nonce = 0;
    $gasPrice = 10;
    $gasLimit = 21000;
	$raw = $wallet->createTransaction($account['address'], $to, '0.0002', $account['private_key'], $nonce, $gasPrice, $gasLimit);
	echo $wallet->sendTransaction($raw); //0xa91377938abd362e2486398d467a6c7c96b1100424ef1d20318e82bffbd8f0e8
}catch (Exception $exception){
	echo $exception->getMessage();
}
```

## Crypto

[![Ethereum](https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/color/eth.png) 0x05836377EB43a0Fe0d88C0D75E101396eAbbb8fb][Ethereum]

[![Binance](https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/color/bnb.png) 0x9C2E46Ca7FA1F483C7CE40a415801351a73FEd90][Binance]

[Ethereum]: https://etherscan.io/address/0x05836377EB43a0Fe0d88C0D75E101396eAbbb8fb "Donate with Ethereum"

[Binance]: https://bscscan.com/address/0x9C2E46Ca7FA1F483C7CE40a415801351a73FEd90 "Donate with Binance Smart Chain"