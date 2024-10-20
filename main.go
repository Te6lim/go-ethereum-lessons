package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

func main() {

	// this is the entry point into the ethereum network
	client, err := ethclient.Dial("https://cloudflare-eth.com")
	//client, err := ethclient.Dial("wss://ropsten.infura.io/_ws")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("we have a connection")

	_ = client

	//AccountBalances(*client)

	//GeneratingNewWallets()

	//Keystores()

	//AddressCheck(*client)

	//QueryingBlocks(*client)

	//QueryingTransactions(*client)

	//TransferringEth(*client)

	//TransferringERC20Tokens(*client)

	//SubscribingToBlocks(*client)

	//CreateRawTransaction(*client)

	//SendRawTransactionData(*client)

}

func AccountBalances(client ethclient.Client) {
	// account balances
	// In order to use account addresses with go ethereum, you must convert them to the go-ethereum common.Address type
	address := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

	fmt.Println(address.Hex())
	fmt.Println(address.Bytes())
	balance, err := client.BalanceAt(context.Background(), address, nil)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("balance is: %v\n", balance)

	// you can also pass the block number to check a balance
	// a block number must be a big.Int
	blockNumber := big.NewInt(5532993)
	weiBalance, err := client.BalanceAt(context.Background(), address, blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("balance via block number: %v\n", weiBalance)

	// pending account balance
	pendingBalance, err := client.PendingBalanceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pending account balance: %v\n", pendingBalance)

	// converting to value in eth
	fBalance := new(big.Float)
	fBalance.SetString(weiBalance.String())
	ethValue := new(big.Float).Quo(fBalance, big.NewFloat(math.Pow10(18)))
	fmt.Printf("eth value: %v\n", ethValue)
}

func GeneratingNewWallets() {
	// generating new wallets
	// genrate a random private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Printf("private key hex: %v\n", hexutil.Encode(privateKeyBytes)[2:])

	// a public key can be deriveed from the private key
	publicKey := privateKey.Public()
	// converting it to hex is a similar process that we went through with the private key. we strip off the 0x and the first 2 characters 04 which is always the EC prefix and is not required.
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot asset type: public key is not of type *ecdsa.PublicKey")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Printf("public key hex: %v\n", hexutil.Encode(publicKeyBytes)[4:])

	// now that we have the public key and the private key, we can generate a public address
	walletAddress := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Printf("wallet address: %v\n", walletAddress)
}

func Keystores() {
	// a keystore is a file containing an encrypted wallet private key. a key store can contain only one wallet key pair per file
	/*ks := keystore.NewKeyStore("./wallets", keystore.StandardScryptN, keystore.StandardScryptP)
	password := "secret"

	account, err := ks.NewAccount(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("account in key store: %v\n", account.Address.Hex())*/

	// importing the keystore
	file := "./wallets/UTC--2024-10-18T19-27-06.187617000Z--adf0758a5fe3b6443248f582b6f472167f6a0d66"
	ks := keystore.NewKeyStore("./tmp", keystore.StandardScryptN, keystore.StandardScryptP)
	jsonBytes, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	passoword_1 := "secret"
	account, err := ks.Import(jsonBytes, passoword_1, passoword_1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("account in keystore: %v\n", account.Address.Hex())
	if err := os.Remove(file); err != nil {
		log.Fatal(err)
	}
}

func AddressCheck(client ethclient.Client) {
	// we can determine if an address is a smart contract if there bytecode stored at that address else it is a standard ethereum account
	address := common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498")
	bytecode, err := client.CodeAt(context.Background(), address, nil)
	if err != nil {
		log.Fatal(err)
	}

	isContract := len(bytecode) > 0

	fmt.Printf("is contract: %v\n", isContract)
}

// TRANSACTIONS

func QueryingBlocks(client ethclient.Client) {
	header, err := client.HeaderByNumber(context.Background(), nil /* latest header is returned*/)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("the block number is: %v\n", header.Number.String())

	/* Call the client's BlockByNumber method to get the full block.
	You can read all the contents and metadata of the block such as block number,
	block timestamp, block hash, block difficulty, as well as the list of transactions and much much more.*/
	blockNumber := big.NewInt(5671744)
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("the block number is %v\n", block.Number().Uint64())
	fmt.Printf("the block time is %v\n", block.Time())
	fmt.Printf("the block difficulty is %v\n", block.Difficulty().Uint64())
	fmt.Printf("the block hash is %v\n", block.Hash().Hex())
	fmt.Printf("length of transactions: %v\n", len(block.Transactions()))
	count, err := client.TransactionCount(context.Background(), block.Hash())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("length of transactions is %v\n", count)

	//querying transactions
	for _, tx := range block.Transactions() {
		/* each transaction has a receipt which contains the result of the execution of the transaction,
		such as any return values and logs, as well as the status which will be 1 (success) or 0 (fail).*/
		receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("status: %v\n", receipt.Status)
		fmt.Printf("logs: %v\n", receipt.Logs)
	}
}

func QueryingTransactions(client ethclient.Client) {
	// iterating over transactions without fetching the block
	blockHash := common.HexToHash("0x9e8751ebb5069389b855bba72d94902cc385042661498a415979b7b6ee9ba4b9")
	count, err := client.TransactionCount(context.Background(), blockHash)
	if err != nil {
		log.Fatal(err)
	}

	for idx := uint(0); idx < count; idx++ {
		tx, err := client.TransactionInBlock(context.Background(), blockHash, idx)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("transaction hex: %v\n", tx.Hash().Hex())
	}

	// transaction by hash
	txHash := common.HexToHash("0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2")
	tx_1, isPending, err_1 := client.TransactionByHash(context.Background(), txHash)
	if err_1 != nil {
		log.Fatal(err)
	}
	fmt.Printf("transaction hex: %v\n", tx_1.Hash().Hex())
	fmt.Println(isPending)
}

func TransferringEth(client ethclient.Client) {
	/* a transaction consists of the amount of ether you're transferring, the gas limit, the gas price, a nonce, the receiving address, and optionally data.
	The transaction must be signed with the private key of the sender before it's broadcasted to the network.*/
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// eth in wei
	value := big.NewInt(1000000000000000000)

	// gas limit
	gasLimit := uint64(21000)

	// gas price
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// receiver of eth
	toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	// the next step is to sign the transaction with the private key of the sender
	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s\n", signedTx.Hash().Hex())
}

func TransferringERC20Tokens(client ethclient.Client) {

}

func SubscribingToBlocks(client ethclient.Client) {
	headers := make(chan *types.Header)

	sub, err := client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			fmt.Printf("header: %v\n", header.Hash().Hex())
			block, err := client.BlockByHash(context.Background(), header.Hash())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("block hex: %v\n", block.Hash().Hex())
			fmt.Printf("bloch number: %v\n", block.Number().Uint64())
			fmt.Printf("block time: %v\n", block.Time())
			fmt.Printf("block nonce: %v\n", block.Nonce())
			fmt.Printf("block transaction length: %v\n", len(block.Transactions()))
		}
	}
}

func CreateRawTransaction(client ethclient.Client) {

	/* a transaction consists of the amount of ether you're transferring, the gas limit, the gas price, a nonce, the receiving address, and optionally data.
	The transaction must be signed with the private key of the sender before it's broadcasted to the network.*/
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// eth in wei
	value := big.NewInt(1000000000000000000)

	// gas limit
	gasLimit := uint64(21000)

	// gas price
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// receiver of eth
	toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")

	var data []byte

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	// the next step is to sign the transaction with the private key of the sender
	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	/* now before we can get the transaction in raw bytes format we'll need to initialize a types.
	ransactions type with the signed transaction as the first value.*/

	/* the reason for doing this is because the Transactions type provides a GetRlp method for returning the transaction in RLP encoded format.
	RLP is a special encoding method Ethereum uses for serializing objects. the result of this is raw bytes.*/
	ts := types.Transactions{signedTx}

	rawTxBytes, err := rlp.EncodeToBytes(ts[0])
	if err != nil {
		log.Fatal(err)
	}
	rawTxHex := hex.EncodeToString(rawTxBytes)
	fmt.Printf("raw transaction data: %s\n", rawTxHex)
}

func SendRawTransactionData(client ethclient.Client) {
	rawTx := "f86c088501c712ac2a825208944592d8f8d7b001e72cb26a73e4fa1806a51ac79d880de0b6b3a76400008026a0b74ba741ae20e7347d330954e795fbede8450c2fbc034d5739b4d1a8056cbcd6a0150b274a561204b88824c7290999b8485df18dc8922398925d20093bdf7a9d76"
	rawTxBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		log.Fatal(err)
	}

	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)

	err_1 := client.SendTransaction(context.Background(), tx)
	if err_1 != nil {
		log.Fatal(err_1)
	}

	fmt.Printf("tx sent: %s\n", tx.Hash().Hex())
}
