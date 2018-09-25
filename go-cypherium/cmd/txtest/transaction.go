// This file is used to benchmark the speed of transaction verification
// build:
// 	go to the top directory, type: make txtest, then executable file can be found in build/bin
// run:
//  ./build/bin/txtest
//
// Test results:
// Use EIP155 plus ED25519 to verify transaction signature (10000 times), time elapsed:    1.604913 seconds
// Use native ED25519 to verify transaction signature (10000 times), time elapsed:         1.554256 seconds
// Generate hash values (10000 times), time elapsed:                                       0.027268 seconds
// Use native secp256k1 to verify transaction signature (10000 times), time elapsed:       1.714036 seconds
// DeriveSHA from 1000 transactions, time elapsed:                                         0.004769 seconds

package main

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/cyphertestnet/go-cypherium/common"
	"github.com/cyphertestnet/go-cypherium/common/hexutil"
	"github.com/cyphertestnet/go-cypherium/core/types"
	"github.com/cyphertestnet/go-cypherium/crypto"
	"golang.org/x/crypto/ed25519"
)

func testDeriveSHA() time.Duration {
	txList := types.Transactions{}
	publicKey, privateKey, _ := ed25519.GenerateKey(crand.Reader)

	tx := types.NewTransaction(100, common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"), big.NewInt(10000000000000000), uint64(21000), big.NewInt(2100000000), []byte{})
	signer := types.NewEIP155Signer(big.NewInt(200))
	signedTx, _ := types.SignTxWithED25519(tx, signer, privateKey, publicKey)

	for i := 0; i < 1000; i++ {
		txList = append(txList, []*types.Transaction{signedTx}...)
	}

	start := time.Now()
	types.DeriveSha(txList)
	elapsed := time.Now().Sub(start)

	return elapsed
}

const COUNT = 10000

func main() {
	publicKey, privateKey, _ := ed25519.GenerateKey(crand.Reader)

	tx := types.NewTransaction(100, common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"), big.NewInt(10000000000000000), uint64(21000), big.NewInt(2100000000), []byte{})
	signer := types.NewEIP155Signer(big.NewInt(200))
	signedTx, _ := types.SignTxWithED25519(tx, signer, privateKey, publicKey)

	start := time.Now()
	for i := 0; i < COUNT; i++ {
		signer.Sender(signedTx)
	}
	elapsed := time.Now().Sub(start)

	fmt.Printf("Use EIP155 plus ED25519 to verify transaction signature (%d times), time elapsed: \t%f seconds\n", COUNT, elapsed.Seconds())

	////////////////////////////////////////////////

	hash := signer.Hash(tx)

	sig, _ := crypto.SignWithED25519(hash[:], privateKey)

	start = time.Now()
	for i := 0; i < COUNT; i++ {
		ed25519.Verify(publicKey, hash[:], sig)
	}
	elapsed = time.Now().Sub(start)

	fmt.Printf("Use native ED25519 to verify transaction signature (%d times), time elapsed: \t%f seconds\n", COUNT, elapsed.Seconds())

	////////////////////////////////////////////////
	start = time.Now()
	for i := 0; i < COUNT; i++ {
		signer.Hash(tx)
	}
	elapsed = time.Now().Sub(start)

	fmt.Printf("Generate hash values (%d times), time elapsed: \t\t\t\t\t%f seconds\n", COUNT, elapsed.Seconds())

	////////////////////////////////////////////////

	var (
		testmsg    = hexutil.MustDecode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
		testsig    = hexutil.MustDecode("0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
		testpubkey = hexutil.MustDecode("0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
	)

	sig = testsig[:len(testsig)-1] // remove recovery id

	start = time.Now()
	for i := 0; i < COUNT; i++ {
		if !crypto.VerifySignature(testpubkey, testmsg, sig) {
			fmt.Println("can't verify signature with uncompressed key")
			break
		}
	}
	elapsed = time.Now().Sub(start)

	fmt.Printf("Use native secp256k1 to verify transaction signature (%d times), time elapsed: \t%f seconds\n", COUNT, elapsed.Seconds())

	elapsed = testDeriveSHA()
	fmt.Printf("DeriveSHA from 1000 transactions, time elapsed: \t\t\t\t\t%f seconds\n", elapsed.Seconds())
}
