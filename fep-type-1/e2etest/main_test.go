package testaggoracle

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/0xPolygon/cdk-contracts-tooling/contracts/banana/polygonzkevmbridgev2"
	gerContractL1 "github.com/0xPolygon/cdk-contracts-tooling/contracts/banana/polygonzkevmglobalexitrootv2"
	gerl2 "github.com/0xPolygon/cdk-contracts-tooling/contracts/sovereign/globalexitrootmanagerl2sovereignchain"
	"github.com/0xPolygon/cdk/bridgesync"
	"github.com/0xPolygon/cdk/claimsponsor"
	"github.com/0xPolygon/cdk/l1infotreesync"
	"github.com/0xPolygon/cdk/log"
	cdkClient "github.com/0xPolygon/cdk/rpc/client"
	"github.com/0xPolygonHermez/zkevm-node/etherman/smartcontracts/polygonzkevmbridge"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/invocarnau/succint-zk-residency/goutils/contracts/transparentupgradableproxy"
	"github.com/stretchr/testify/require"
)

const (
	logColumnWidth = 80

	l1URL                         = "http://127.0.0.1:58669" // kurtosis port print cdk el-1-geth-lighthouse rpc
	l1ChainID                     = 271828
	l1RollupAddrHex               = "0x2F50ef6b8e8Ee4E579B17619A92dE3E2ffbD8AD2"
	l1BridgeAddrHex               = "0xD71f8F956AD979Cc2988381B8A743a2fE280537D"
	l1GERManagerAddrHex           = "0x1f7ad7caA53e35b4f0D138dC5CBF91aC108a2674"
	l1PrefundedPrivatekey         = "0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31" // 0x8943545177806ED17B9F23F0a21ee5948eCaa776
	l1BridgeAssetSenderPrivateKey = l1PrefundedPrivatekey

	l2URL                    = "http://127.0.0.1:58971" // kurtosis port print cdk op-el-1-op-geth-op-node-op-kurtosis rpc
	l2ChainID                = 2151908
	l2NetworkID              = uint32(2)
	l2PrefundedPrivatekey    = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	l2ClaimSponsorAddrHex    = "0x5f5dB0D4D58310F53713eF4Df80ba6717868A9f8"                         // needed to fund this account
	l2AggOracleSenderAddrHex = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"                         // needed to fund this account
	l2BridgeReceiverAddrHex  = "0x00babaca00babaca00babaca00babaca00babaca"
	l2BridgeServiceURL       = "http://127.0.0.1:5576" // this is the RPC running inside of the AggOracle container

	// these parameters are used when you already executed the test once and want
	// to run the test again without deploying the contracts again
	// the first run of the test will log the addresses of the deployed contracts
	// you can set the deployed to true and copy them here to avoid deploying the
	// contracts again
	deployed                = true
	preDeployedGERAddrL2    = "0x6F9a46C1B4bbea11f7364E0B81024b1715E85A77"
	preDeployedBridgeAddrL2 = "0x9C819855CEB276D74978F205aE4481083468bBAF"
)

func TestBridgeEVM(t *testing.T) {
	ctx := context.Background()

	authL1 := mustGetAuth(l1BridgeAssetSenderPrivateKey, l1ChainID)
	authL2 := mustGetAuth(l2PrefundedPrivatekey, l2ChainID)

	fmt.Println("connecting to L1")
	clientL1, gerL1, bridgeL1 := connectToL1(t, authL1)
	fmt.Println("L1 connected!")
	fmt.Println("")
	fmt.Println("preparing and connecting to L2")
	clientL2, gerAddrL2, gerL2, bridgeAddrL2, bridgeL2 := prepareAndConnectToL2(t, authL2)
	fmt.Println("L2 prepared and connected!")
	fmt.Println("")

	fmt.Println("running Agg Oracle")
	editConfig(t, gerAddrL2, bridgeAddrL2)
	runAggOracle(t)
	fmt.Println("")

	fmt.Println("bridging assets ")
	fmt.Println("")
	go bridgeAssets(t,
		clientL1, authL1, bridgeL1, gerL1,
		authL2, bridgeL2,
	)

	go balanceMonitor(t, authL1, clientL1, clientL2)

	fmt.Println("watching for InsertGlobalExitRoot events")
	fmt.Println("")
	watchInsertGEREvents(ctx, t, clientL2, gerL2, gerAddrL2)
}

func balanceMonitor(t *testing.T, authL1 *bind.TransactOpts, clientL1, clientL2 *ethclient.Client) {
	for {
		senderAddr := authL1.From
		senderBalance, err := clientL1.BalanceAt(context.Background(), senderAddr, nil)
		require.NoError(t, err)
		senderDesc := fmt.Sprintf("SENDER %v: %v", senderAddr.String(), senderBalance.String())

		receiverAddr := common.HexToAddress(l2BridgeReceiverAddrHex)
		receiverBalance, err := clientL2.BalanceAt(context.Background(), receiverAddr, nil)
		require.NoError(t, err)
		receiverDesc := fmt.Sprintf("RECEIVER %v: %v", receiverAddr.String(), receiverBalance.String())

		fmt.Println()
		fmt.Println("BALANCES:")
		fmt.Println(senderDesc, strings.Repeat(" ", logColumnWidth-len(senderDesc)-1), receiverDesc)
		fmt.Println()
		time.Sleep(10 * time.Second)
	}
}

func watchInsertGEREvents(ctx context.Context, t *testing.T, clientL2 *ethclient.Client, gerL2 *gerl2.Globalexitrootmanagerl2sovereignchain, gerAddrL2 common.Address) {
	insertGlobalExitRootHash := crypto.Keccak256Hash([]byte("InsertGlobalExitRoot(bytes32)"))
	_ = insertGlobalExitRootHash
	filter := ethereum.FilterQuery{
		Addresses: []common.Address{gerAddrL2},
		Topics:    [][]common.Hash{{insertGlobalExitRootHash}},
	}

	fromBlock, err := clientL2.BlockNumber(ctx)
	require.NoError(t, err)
	for {
		filter.FromBlock = big.NewInt(0).SetUint64(fromBlock)
		logs, err := clientL2.FilterLogs(ctx, filter)
		require.NoError(t, err)
		for _, l := range logs {
			insertGlobalExitRootLog, err := gerL2.ParseInsertGlobalExitRoot(l)
			require.NoError(t, err)

			newGERHashHex := common.BytesToHash(insertGlobalExitRootLog.NewGlobalExitRoot[:]).String()
			fmt.Println(strings.Repeat(" ", logColumnWidth), "NEW L2 GER:", newGERHashHex)

			if fromBlock <= l.BlockNumber {
				fromBlock = l.BlockNumber + 1
			}
		}
		time.Sleep(time.Second)
	}
}

func connectToL1(t *testing.T, auth *bind.TransactOpts) (
	*ethclient.Client,
	*gerContractL1.Polygonzkevmglobalexitrootv2,
	*polygonzkevmbridge.Polygonzkevmbridge,
) {
	client, err := ethclient.Dial(l1URL)
	require.NoError(t, err)

	gerAddr := common.HexToAddress(l1GERManagerAddrHex)
	gerContract, err := gerContractL1.NewPolygonzkevmglobalexitrootv2(gerAddr, client)
	require.NoError(t, err)

	bridgeAddr := common.HexToAddress(l1BridgeAddrHex)
	bridgeContract, err := polygonzkevmbridge.NewPolygonzkevmbridge(bridgeAddr, client)
	require.NoError(t, err)

	balance, err := client.BalanceAt(context.Background(), auth.From, nil)
	require.NoError(t, err)
	fmt.Println("acc: ", auth.From.String())
	fmt.Println("balance: ", balance)

	return client, gerContract, bridgeContract
}

func prepareAndConnectToL2(t *testing.T, auth *bind.TransactOpts) (
	*ethclient.Client,
	common.Address,
	*gerl2.Globalexitrootmanagerl2sovereignchain,
	common.Address,
	*polygonzkevmbridgev2.Polygonzkevmbridgev2,
) {
	client, err := ethclient.Dial(l2URL)
	require.NoError(t, err)

	if deployed {
		gerAddrL2 := common.HexToAddress(preDeployedGERAddrL2)
		gerContract, err := gerl2.NewGlobalexitrootmanagerl2sovereignchain(gerAddrL2, client)
		require.NoError(t, err)

		bridgeAddrL2 := common.HexToAddress(preDeployedBridgeAddrL2)
		bridgeContract, err := polygonzkevmbridgev2.NewPolygonzkevmbridgev2(bridgeAddrL2, client)
		require.NoError(t, err)

		fmt.Println("L2 using contracts already deployed ", gerAddrL2)
		fmt.Println("L2 GER Addr ", gerAddrL2)
		fmt.Println("L2 Bridge Addr ", bridgeAddrL2)

		return client, gerAddrL2, gerContract, bridgeAddrL2, bridgeContract
	}

	balance, err := client.BalanceAt(context.Background(), auth.From, nil)
	require.NoError(t, err)
	fmt.Println("acc: ", auth.From.String())
	fmt.Println("balance: ", balance)

	// create tmp auth to deploy contracts
	ctx := context.Background()
	privateKeyL2, err := crypto.GenerateKey()
	require.NoError(t, err)
	authDeployer, err := bind.NewKeyedTransactorWithChainID(privateKeyL2, big.NewInt(l2ChainID))
	require.NoError(t, err)

	fmt.Println("deployer acc: ", auth.From.String())

	// fund deployer
	fmt.Println("funding deployer")
	nonce, err := client.PendingNonceAt(ctx, auth.From)
	require.NoError(t, err)
	amountToTransfer, _ := new(big.Int).SetString("1000000000000000000", 10) //nolint:gomnd
	gasPrice, err := client.SuggestGasPrice(ctx)
	require.NoError(t, err)
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{From: auth.From, To: &authDeployer.From, Value: amountToTransfer})
	require.NoError(t, err)
	tx := types.NewTransaction(nonce, authDeployer.From, amountToTransfer, gasLimit, gasPrice, nil)
	signedTx, err := auth.Signer(auth.From, tx)
	require.NoError(t, err)
	err = client.SendTransaction(ctx, signedTx)
	require.NoError(t, err)
	waitTxMined(t, client, signedTx.Hash(), "funding deployer tx not mined")
	balance, err = client.BalanceAt(ctx, authDeployer.From, nil)
	require.NoError(t, err)
	require.Equal(t, amountToTransfer, balance)

	// fund bridge
	fmt.Println("funding bridge")
	precalculatedBridgeAddr := crypto.CreateAddress(authDeployer.From, 1)
	tx = types.NewTransaction(nonce+1, precalculatedBridgeAddr, amountToTransfer, gasLimit, gasPrice, nil)
	signedTx, err = auth.Signer(auth.From, tx)
	require.NoError(t, err)
	err = client.SendTransaction(ctx, signedTx)
	require.NoError(t, err)
	waitTxMined(t, client, signedTx.Hash(), "funding bridge tx not mined")
	balance, err = client.BalanceAt(ctx, precalculatedBridgeAddr, nil)
	require.NoError(t, err)
	require.Equal(t, amountToTransfer, balance)

	// fund claim sponsor
	fmt.Println("funding claim sponsor")
	claimSponsorAddr := common.HexToAddress(l2ClaimSponsorAddrHex)
	tx = types.NewTransaction(nonce+2, claimSponsorAddr, amountToTransfer, gasLimit, gasPrice, nil)
	signedTx, err = auth.Signer(auth.From, tx)
	require.NoError(t, err)
	err = client.SendTransaction(ctx, signedTx)
	require.NoError(t, err)
	waitTxMined(t, client, signedTx.Hash(), "funding claim sponsor tx not mined")
	balance, err = client.BalanceAt(ctx, claimSponsorAddr, nil)
	require.NoError(t, err)
	require.Equal(t, amountToTransfer, balance)

	// deploy bridge impl
	fmt.Println("deploying bridge impl")
	bridgeImplementationAddr, bridgeImplementationTx, _, err := polygonzkevmbridgev2.DeployPolygonzkevmbridgev2(authDeployer, client)
	require.NoError(t, err)
	waitTxMined(t, client, bridgeImplementationTx.Hash(), "bridge deploy not mined")

	// deploy bridge proxy
	fmt.Println("deploying bridge proxy")
	nonce, err = client.PendingNonceAt(ctx, authDeployer.From)
	require.NoError(t, err)
	precalculatedAddr := crypto.CreateAddress(authDeployer.From, nonce+1)
	bridgeABI, err := polygonzkevmbridgev2.Polygonzkevmbridgev2MetaData.GetAbi()
	require.NoError(t, err)
	dataCallProxy, err := bridgeABI.Pack("initialize",
		l2NetworkID,      //network ID
		common.Address{}, // gasTokenAddressMainnet"
		uint32(0),        // gasTokenNetworkMainnet
		precalculatedAddr,
		common.Address{},
		[]byte{}, // gasTokenMetadata
	)
	require.NoError(t, err)
	code, err := client.CodeAt(ctx, bridgeImplementationAddr, nil)
	require.NoError(t, err)
	require.NotEqual(t, len(code), 0)
	bridgeAddr, bridgeTx, _, err := transparentupgradableproxy.DeployTransparentupgradableproxy(
		authDeployer, client, bridgeImplementationAddr, authDeployer.From, dataCallProxy,
	)
	require.NoError(t, err)
	if bridgeAddr != precalculatedBridgeAddr {
		err = fmt.Errorf("error calculating bridge addr. Expected: %s. Actual: %s", precalculatedBridgeAddr, bridgeAddr)
		require.NoError(t, err)
	}
	waitTxMined(t, client, bridgeTx.Hash(), "bridge proxy deploy not mined")
	bridgeContract, err := polygonzkevmbridgev2.NewPolygonzkevmbridgev2(bridgeAddr, client)
	require.NoError(t, err)
	checkGERAddr, err := bridgeContract.GlobalExitRootManager(&bind.CallOpts{})
	require.NoError(t, err)
	if precalculatedAddr != checkGERAddr {
		err = errors.New("error deploying bridge")
		require.NoError(t, err)
	}

	// deploy GER
	fmt.Println("deploying GER")
	gerAddr, gerTx, gerContract, err := gerl2.DeployGlobalexitrootmanagerl2sovereignchain(authDeployer, client, bridgeAddr)
	require.NoError(t, err)
	waitTxMined(t, client, gerTx.Hash(), "GER deploy not mined")
	if precalculatedAddr != gerAddr {
		err = errors.New("error deploying bridge")
		require.NoError(t, err)
	}

	fmt.Println("L2 GER Addr ", gerAddr)
	fmt.Println("L2 Bridge Addr ", bridgeAddr)

	return client, gerAddr, gerContract, bridgeAddr, bridgeContract
}

func editConfig(t *testing.T, gerL2, bridgeL2 common.Address) {
	file, err := os.ReadFile("./config/template_cdk.toml")
	require.NoError(t, err)
	// l1 updates
	updatedConfig := strings.ReplaceAll(string(file), "XXX_GlobalExitRootL1", l1GERManagerAddrHex)
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_BridgeL1", l1BridgeAddrHex)
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_RollupL1", l1RollupAddrHex)
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_chainIDL1", fmt.Sprint(l1ChainID))
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_l1URL", dockerizeLocalURLs(l1URL))

	// l2 updates
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_GlobalExitRootL2", gerL2.String())
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_BridgeL2", bridgeL2.String())
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_chainIDL2", fmt.Sprint(l2ChainID))
	updatedConfig = strings.ReplaceAll(updatedConfig, "XXX_l2URL", dockerizeLocalURLs(l2URL))

	err = os.WriteFile("./config/cdk.toml", []byte(updatedConfig), 0644)
	require.NoError(t, err)
}

func dockerizeLocalURLs(url string) string {
	const dockerLocalDNS = "host.docker.internal"
	url = strings.ReplaceAll(url, "localhost", dockerLocalDNS)
	url = strings.ReplaceAll(url, "127.0.0.1", dockerLocalDNS)
	return url
}

func runAggOracle(t *testing.T) {
	//msg, err := exec.Command("bash", "-l", "-c", "docker compose up -d test-fep-type1-cdk").CombinedOutput()
	msg, err := exec.Command("bash", "-l", "-c", "docker run --name AggOracle --hostname=docker-desktop --env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin --volume=/Users/thiago/github.com/tclemos/succint-zk-residency/fep-type-1/e2etest/config/cdk.toml:/app/config.toml:rw --volume=/Users/thiago/github.com/tclemos/succint-zk-residency/fep-type-1/e2etest/config/aggoracle.keystore:/app/keystore/aggoracle.keystore:rw --volume=/Users/thiago/github.com/tclemos/succint-zk-residency/fep-type-1/e2etest/config/claimsponsor.keystore:/app/keystore/claimsponsor.keystore:rw -p 5576:5576 --restart=no  -d arnaubennassar/cdk:12b8e2c sh -c \"cdk-node run --cfg /app/config.toml --custom-network-file /app/genesis.json --components aggoracle,rpc\"").CombinedOutput()
	if err != nil && !strings.Contains(string(msg), "is already in use by container") {
		require.NoError(t, err, string(msg))
	}
	time.Sleep(time.Second * 2)
}

func bridgeAssets(
	t *testing.T,
	clientL1 *ethclient.Client, authL1 *bind.TransactOpts, bridgeL1 *polygonzkevmbridge.Polygonzkevmbridge, gerL1Contract *gerContractL1.Polygonzkevmglobalexitrootv2,
	authL2 *bind.TransactOpts, bridgeL2 *polygonzkevmbridgev2.Polygonzkevmbridgev2,
) {
	bridgeClient := cdkClient.NewClient(l2BridgeServiceURL)
	currentGER, err := gerL1Contract.GetLastGlobalExitRoot(nil)
	require.NoError(t, err)

	fmt.Println("CUR L1 GER:", common.BytesToHash(currentGER[:]).String())

	for i := 0; i < 1000; i++ {
		// Send bridge L1 -> L2
		// fmt.Println("--- ITERATION ", i)
		// fmt.Println("sending bridge tx to L1")
		amount := big.NewInt(10000000000000000) //nolint:gomnd
		authL1.Value = amount
		claimL1toL2 := claimsponsor.Claim{
			LeafType:           0,
			OriginNetwork:      0,
			OriginTokenAddress: common.Address{},
			DestinationNetwork: l2NetworkID,
			DestinationAddress: common.HexToAddress(l2BridgeReceiverAddrHex),
			Amount:             amount,
			Metadata:           nil,
		}
		gerBefore, err := gerL1Contract.GetLastGlobalExitRoot(nil)
		require.NoError(t, err)

		tx, err := bridgeL1.BridgeAsset(authL1, claimL1toL2.DestinationNetwork, claimL1toL2.DestinationAddress, claimL1toL2.Amount, claimL1toL2.OriginTokenAddress, true, nil)
		require.NoError(t, err)
		waitTxMined(t, clientL1, tx.Hash(), "bridge asset tx not mined")

		gerAfter, err := gerL1Contract.GetLastGlobalExitRoot(nil)
		require.NoError(t, err)
		require.NotEqual(t, gerBefore, gerAfter, "GER not updated on L1")
		// fmt.Printf("GER updated on L1 from %v to %v\n", common.BytesToHash(gerBefore[:]).String(), common.BytesToHash(gerAfter[:]).String())
		fmt.Println("NEW L1 GER:", common.BytesToHash(gerAfter[:]).String())

		// claim on L2
		depositCountBig, err := bridgeL1.DepositCount(nil)
		require.NoError(t, err)

		depositCount := uint32(depositCountBig.Uint64())
		depositCount--

		var bridgeIncludedAtIndex uint32
		found := false
		for i := 0; i < 40; i++ { // block needs to be finalised, takes ~32s
			bridgeIncludedAtIndex, err = bridgeClient.L1InfoTreeIndexForBridge(0, depositCount)
			if err == nil {
				found = true
				break
			}
			time.Sleep(time.Second * 2)
		}
		require.True(t, found)
		// fmt.Println("Bridge included at L1 Info Tree Index: ", bridgeIncludedAtIndex)

		// fmt.Println("getting info already injected on L2")
		var info *l1infotreesync.L1InfoTreeLeaf
		found = false
		for i := 0; i < 34; i++ {
			info, err = bridgeClient.InjectedInfoAfterIndex(l2NetworkID, bridgeIncludedAtIndex)
			if err == nil {
				found = true
				break
			}
			time.Sleep(time.Second * 2)
		}
		require.True(t, found)
		require.NoError(t, err)
		// fmt.Printf("Info associated to the first GER injected on L2 after index %d: %+v\n", bridgeIncludedAtIndex, info)
		proof, err := bridgeClient.ClaimProof(0, depositCount, info.L1InfoTreeIndex)
		require.NoError(t, err)
		// fmt.Printf("ClaimProof received from bridge service\n")

		// fmt.Println("Requesting service to sponsor claim")
		claimL1toL2.ProofLocalExitRoot = proof.ProofLocalExitRoot
		claimL1toL2.ProofRollupExitRoot = proof.ProofRollupExitRoot
		claimL1toL2.GlobalIndex = bridgesync.GenerateGlobalIndex(true, claimL1toL2.DestinationNetwork-1, depositCount)
		claimL1toL2.MainnetExitRoot = info.MainnetExitRoot
		claimL1toL2.RollupExitRoot = info.RollupExitRoot
		err = bridgeClient.SponsorClaim(claimL1toL2)
		require.NoError(t, err)
		// fmt.Println("waiting for service to send claim on behalf of the user...")
		found = false
		for i := 0; i < 20; i++ {
			time.Sleep(time.Second * 2)
			status, err := bridgeClient.GetSponsoredClaimStatus(claimL1toL2.GlobalIndex)
			// fmt.Println("sponsored claim status: ", status)
			if err != nil {
				// fmt.Println("error getting sponsored claim status: ", err)
				continue
			}
			require.NotEqual(t, claimsponsor.FailedClaimStatus, status)
			if status == claimsponsor.SuccessClaimStatus {
				found = true
				break
			}
		}
		require.True(t, found)
		// fmt.Println("service reports that the claim tx is successful")

		// check that the bridge is claimed on L2
		// fmt.Println("checking if bridge is claimed on L2...")
		isClaimed, err := bridgeL2.IsClaimed(&bind.CallOpts{}, depositCount, 0)
		require.NoError(t, err)
		require.True(t, isClaimed)
		// fmt.Println("bridge completed!")
	}
}

func waitTxMined(t *testing.T, c *ethclient.Client, hash common.Hash, msg string) {
	// fmt.Println("waiting for tx to be mined: " + hash.String())
	p := false
	var err error
	for i := 0; i < 600; i++ {
		_, p, err = c.TransactionByHash(context.Background(), hash)
		require.NoError(t, err)
		if !p {
			// fmt.Println("mined!")
			break
		}
		time.Sleep(time.Second)
	}
	if len(msg) > 0 {
		require.False(t, p, msg)
	} else {
		require.False(t, p)
	}
}

func estimateTx(ctx context.Context, client *ethclient.Client, from common.Address, tx *types.Transaction) (*big.Int, error) {
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From:     from,
		To:       tx.To(),
		Value:    tx.Value(),
		Data:     tx.Data(),
		Gas:      tx.Gas(),
		GasPrice: tx.GasPrice(),
	})
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasLimit)), nil
}

func txRevertMessage(ctx context.Context, client *ethclient.Client, tx *types.Transaction) (string, error) {
	if tx == nil {
		return "", nil
	}

	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		return "", err
	}

	if receipt.Status == types.ReceiptStatusFailed {
		revertMessage, err := txRevertReason(ctx, client, tx, receipt.BlockNumber)
		if err != nil {
			return "", err
		}
		return revertMessage, nil
	}
	return "", nil
}

func txRevertReason(ctx context.Context, c *ethclient.Client, tx *types.Transaction, blockNumber *big.Int) (string, error) {
	if tx == nil {
		return "", nil
	}

	from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
	if err != nil {
		signer := types.LatestSignerForChainID(tx.ChainId())
		from, err = types.Sender(signer, tx)
		if err != nil {
			return "", err
		}
	}
	msg := ethereum.CallMsg{
		From: from,
		To:   tx.To(),
		Gas:  tx.Gas(),

		Value: tx.Value(),
		Data:  tx.Data(),
	}
	hex, err := c.CallContract(ctx, msg, blockNumber)
	if err != nil {
		return "", err
	}

	unpackedMsg, err := abi.UnpackRevert(hex)
	if err != nil {
		log.Warnf("failed to get the revert message for tx %v: %v", tx.Hash(), err)
		return "", errors.New("execution reverted")
	}

	return unpackedMsg, nil
}

func getAuth(privateKeyStr string, chainID uint64) (*bind.TransactOpts, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyStr, "0x"))
	if err != nil {
		return nil, err
	}

	return bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(0).SetUint64(chainID))
}

func mustGetAuth(privateKeyStr string, chainID uint64) *bind.TransactOpts {
	auth, err := getAuth(privateKeyStr, chainID)
	if err != nil {
		panic(err)
	}
	return auth
}
