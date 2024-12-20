// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package gerl2

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// Gerl2MetaData contains all meta data concerning the Gerl2 contract.
var Gerl2MetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_bridgeAddress\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"GlobalExitRootAlreadySet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"OnlyAllowedContracts\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"OnlyCoinbase\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"newGlobalExitRoot\",\"type\":\"bytes32\"}],\"name\":\"InsertGlobalExitRoot\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"bridgeAddress\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32[]\",\"name\":\"globalExitRoots\",\"type\":\"bytes32[]\"}],\"name\":\"checkGERsExistance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"previousInjectedGERCount\",\"type\":\"uint256\"},{\"internalType\":\"bytes32[]\",\"name\":\"injectedGERs\",\"type\":\"bytes32[]\"}],\"name\":\"checkInjectedGERsAndReturnLER\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"localExitRoot\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"globalExitRootMap\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"injectedGERCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_newRoot\",\"type\":\"bytes32\"}],\"name\":\"insertGlobalExitRoot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_newRoot\",\"type\":\"bytes32\"}],\"name\":\"insertGlobalExitRoot_cheat\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"lastRollupExitRoot\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"newRoot\",\"type\":\"bytes32\"}],\"name\":\"updateExitRoot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x60a060405234801561000f575f80fd5b5060405161071938038061071983398101604081905261002e9161003f565b6001600160a01b031660805261006c565b5f6020828403121561004f575f80fd5b81516001600160a01b0381168114610065575f80fd5b9392505050565b60805161068e61008b5f395f818161014a01526102a1015261068e5ff3fe608060405234801561000f575f80fd5b506004361061009f575f3560e01c80636212cd48116100725780639175042711610058578063917504271461013c578063a3c573eb14610145578063cc9794cf14610191575f80fd5b80636212cd48146101065780636b37f64b14610129575f80fd5b806301fd9044146100a357806312da06b2146100bf578063257b3632146100d457806333d6247d146100f3575b5f80fd5b6100ac60015481565b6040519081526020015b60405180910390f35b6100d26100cd36600461041e565b6101bb565b005b6100ac6100e236600461041e565b5f6020819052908152604090205481565b6100d261010136600461041e565b610289565b610119610114366004610435565b6102fd565b60405190151581526020016100b6565b6100d261013736600461041e565b6101f4565b6100ac60345481565b61016c7f000000000000000000000000000000000000000000000000000000000000000081565b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020016100b6565b6101a461019f3660046104d1565b61035e565b6040805192151583526020830191909152016100b6565b4133146101f4576040517f116c64a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8181526020819052604081205490036102575760345f8154610216906105e1565b91829055505f8281526020819052604080822092909255905182917fb1b866fe5fac68e8f1a4ab2520c7a6b493a954934bbd0f054bd91d6674a4c0d591a250565b6040517f1f97a58200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000000000000000000000000000000000016146102f8576040517fb49365dd00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600155565b5f805b82811015610352575f8085858481811061031c5761031c610618565b9050602002013581526020019081526020015f20545f03610340575f915050610358565b8061034a816105e1565b915050610300565b50600190505b92915050565b6034545f9081908085111561037957505f9150819050610417565b5f6103848683610645565b9050855f5b828110156103f0578161039b816105e1565b925050815f808984815181106103b3576103b3610618565b602002602001015181526020019081526020015f2054146103de57505f945084935061041792505050565b806103e8816105e1565b915050610389565b50828103610408576001805494509450505050610417565b505f9350839250610417915050565b9250929050565b5f6020828403121561042e575f80fd5b5035919050565b5f8060208385031215610446575f80fd5b823567ffffffffffffffff8082111561045d575f80fd5b818501915085601f830112610470575f80fd5b81358181111561047e575f80fd5b8660208260051b8501011115610492575f80fd5b60209290920196919550909350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b5f80604083850312156104e2575f80fd5b8235915060208084013567ffffffffffffffff80821115610501575f80fd5b818601915086601f830112610514575f80fd5b813581811115610526576105266104a4565b8060051b6040517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0603f83011681018181108582111715610569576105696104a4565b604052918252848201925083810185019189831115610586575f80fd5b938501935b828510156105a45784358452938501939285019261058b565b8096505050505050509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610611576106116105b4565b5060010190565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b81810381811115610358576103586105b456fea264697066735822122078cefdcc8559bfe58b65db9523e916108fd1f52c2ec69480e0853b94cc9d481c64736f6c63430008140033",
}

// Gerl2ABI is the input ABI used to generate the binding from.
// Deprecated: Use Gerl2MetaData.ABI instead.
var Gerl2ABI = Gerl2MetaData.ABI

// Gerl2Bin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use Gerl2MetaData.Bin instead.
var Gerl2Bin = Gerl2MetaData.Bin

// DeployGerl2 deploys a new Ethereum contract, binding an instance of Gerl2 to it.
func DeployGerl2(auth *bind.TransactOpts, backend bind.ContractBackend, _bridgeAddress common.Address) (common.Address, *types.Transaction, *Gerl2, error) {
	parsed, err := Gerl2MetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(Gerl2Bin), backend, _bridgeAddress)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Gerl2{Gerl2Caller: Gerl2Caller{contract: contract}, Gerl2Transactor: Gerl2Transactor{contract: contract}, Gerl2Filterer: Gerl2Filterer{contract: contract}}, nil
}

// Gerl2 is an auto generated Go binding around an Ethereum contract.
type Gerl2 struct {
	Gerl2Caller     // Read-only binding to the contract
	Gerl2Transactor // Write-only binding to the contract
	Gerl2Filterer   // Log filterer for contract events
}

// Gerl2Caller is an auto generated read-only Go binding around an Ethereum contract.
type Gerl2Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Gerl2Transactor is an auto generated write-only Go binding around an Ethereum contract.
type Gerl2Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Gerl2Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type Gerl2Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Gerl2Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type Gerl2Session struct {
	Contract     *Gerl2            // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// Gerl2CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type Gerl2CallerSession struct {
	Contract *Gerl2Caller  // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// Gerl2TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type Gerl2TransactorSession struct {
	Contract     *Gerl2Transactor  // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// Gerl2Raw is an auto generated low-level Go binding around an Ethereum contract.
type Gerl2Raw struct {
	Contract *Gerl2 // Generic contract binding to access the raw methods on
}

// Gerl2CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type Gerl2CallerRaw struct {
	Contract *Gerl2Caller // Generic read-only contract binding to access the raw methods on
}

// Gerl2TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type Gerl2TransactorRaw struct {
	Contract *Gerl2Transactor // Generic write-only contract binding to access the raw methods on
}

// NewGerl2 creates a new instance of Gerl2, bound to a specific deployed contract.
func NewGerl2(address common.Address, backend bind.ContractBackend) (*Gerl2, error) {
	contract, err := bindGerl2(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Gerl2{Gerl2Caller: Gerl2Caller{contract: contract}, Gerl2Transactor: Gerl2Transactor{contract: contract}, Gerl2Filterer: Gerl2Filterer{contract: contract}}, nil
}

// NewGerl2Caller creates a new read-only instance of Gerl2, bound to a specific deployed contract.
func NewGerl2Caller(address common.Address, caller bind.ContractCaller) (*Gerl2Caller, error) {
	contract, err := bindGerl2(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &Gerl2Caller{contract: contract}, nil
}

// NewGerl2Transactor creates a new write-only instance of Gerl2, bound to a specific deployed contract.
func NewGerl2Transactor(address common.Address, transactor bind.ContractTransactor) (*Gerl2Transactor, error) {
	contract, err := bindGerl2(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &Gerl2Transactor{contract: contract}, nil
}

// NewGerl2Filterer creates a new log filterer instance of Gerl2, bound to a specific deployed contract.
func NewGerl2Filterer(address common.Address, filterer bind.ContractFilterer) (*Gerl2Filterer, error) {
	contract, err := bindGerl2(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &Gerl2Filterer{contract: contract}, nil
}

// bindGerl2 binds a generic wrapper to an already deployed contract.
func bindGerl2(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := Gerl2MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Gerl2 *Gerl2Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Gerl2.Contract.Gerl2Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Gerl2 *Gerl2Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gerl2.Contract.Gerl2Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Gerl2 *Gerl2Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Gerl2.Contract.Gerl2Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Gerl2 *Gerl2CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Gerl2.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Gerl2 *Gerl2TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gerl2.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Gerl2 *Gerl2TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Gerl2.Contract.contract.Transact(opts, method, params...)
}

// BridgeAddress is a free data retrieval call binding the contract method 0xa3c573eb.
//
// Solidity: function bridgeAddress() view returns(address)
func (_Gerl2 *Gerl2Caller) BridgeAddress(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "bridgeAddress")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// BridgeAddress is a free data retrieval call binding the contract method 0xa3c573eb.
//
// Solidity: function bridgeAddress() view returns(address)
func (_Gerl2 *Gerl2Session) BridgeAddress() (common.Address, error) {
	return _Gerl2.Contract.BridgeAddress(&_Gerl2.CallOpts)
}

// BridgeAddress is a free data retrieval call binding the contract method 0xa3c573eb.
//
// Solidity: function bridgeAddress() view returns(address)
func (_Gerl2 *Gerl2CallerSession) BridgeAddress() (common.Address, error) {
	return _Gerl2.Contract.BridgeAddress(&_Gerl2.CallOpts)
}

// CheckGERsExistance is a free data retrieval call binding the contract method 0x6212cd48.
//
// Solidity: function checkGERsExistance(bytes32[] globalExitRoots) view returns(bool success)
func (_Gerl2 *Gerl2Caller) CheckGERsExistance(opts *bind.CallOpts, globalExitRoots [][32]byte) (bool, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "checkGERsExistance", globalExitRoots)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// CheckGERsExistance is a free data retrieval call binding the contract method 0x6212cd48.
//
// Solidity: function checkGERsExistance(bytes32[] globalExitRoots) view returns(bool success)
func (_Gerl2 *Gerl2Session) CheckGERsExistance(globalExitRoots [][32]byte) (bool, error) {
	return _Gerl2.Contract.CheckGERsExistance(&_Gerl2.CallOpts, globalExitRoots)
}

// CheckGERsExistance is a free data retrieval call binding the contract method 0x6212cd48.
//
// Solidity: function checkGERsExistance(bytes32[] globalExitRoots) view returns(bool success)
func (_Gerl2 *Gerl2CallerSession) CheckGERsExistance(globalExitRoots [][32]byte) (bool, error) {
	return _Gerl2.Contract.CheckGERsExistance(&_Gerl2.CallOpts, globalExitRoots)
}

// CheckInjectedGERsAndReturnLER is a free data retrieval call binding the contract method 0xcc9794cf.
//
// Solidity: function checkInjectedGERsAndReturnLER(uint256 previousInjectedGERCount, bytes32[] injectedGERs) view returns(bool success, bytes32 localExitRoot)
func (_Gerl2 *Gerl2Caller) CheckInjectedGERsAndReturnLER(opts *bind.CallOpts, previousInjectedGERCount *big.Int, injectedGERs [][32]byte) (struct {
	Success       bool
	LocalExitRoot [32]byte
}, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "checkInjectedGERsAndReturnLER", previousInjectedGERCount, injectedGERs)

	outstruct := new(struct {
		Success       bool
		LocalExitRoot [32]byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Success = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.LocalExitRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)

	return *outstruct, err

}

// CheckInjectedGERsAndReturnLER is a free data retrieval call binding the contract method 0xcc9794cf.
//
// Solidity: function checkInjectedGERsAndReturnLER(uint256 previousInjectedGERCount, bytes32[] injectedGERs) view returns(bool success, bytes32 localExitRoot)
func (_Gerl2 *Gerl2Session) CheckInjectedGERsAndReturnLER(previousInjectedGERCount *big.Int, injectedGERs [][32]byte) (struct {
	Success       bool
	LocalExitRoot [32]byte
}, error) {
	return _Gerl2.Contract.CheckInjectedGERsAndReturnLER(&_Gerl2.CallOpts, previousInjectedGERCount, injectedGERs)
}

// CheckInjectedGERsAndReturnLER is a free data retrieval call binding the contract method 0xcc9794cf.
//
// Solidity: function checkInjectedGERsAndReturnLER(uint256 previousInjectedGERCount, bytes32[] injectedGERs) view returns(bool success, bytes32 localExitRoot)
func (_Gerl2 *Gerl2CallerSession) CheckInjectedGERsAndReturnLER(previousInjectedGERCount *big.Int, injectedGERs [][32]byte) (struct {
	Success       bool
	LocalExitRoot [32]byte
}, error) {
	return _Gerl2.Contract.CheckInjectedGERsAndReturnLER(&_Gerl2.CallOpts, previousInjectedGERCount, injectedGERs)
}

// GlobalExitRootMap is a free data retrieval call binding the contract method 0x257b3632.
//
// Solidity: function globalExitRootMap(bytes32 ) view returns(uint256)
func (_Gerl2 *Gerl2Caller) GlobalExitRootMap(opts *bind.CallOpts, arg0 [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "globalExitRootMap", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GlobalExitRootMap is a free data retrieval call binding the contract method 0x257b3632.
//
// Solidity: function globalExitRootMap(bytes32 ) view returns(uint256)
func (_Gerl2 *Gerl2Session) GlobalExitRootMap(arg0 [32]byte) (*big.Int, error) {
	return _Gerl2.Contract.GlobalExitRootMap(&_Gerl2.CallOpts, arg0)
}

// GlobalExitRootMap is a free data retrieval call binding the contract method 0x257b3632.
//
// Solidity: function globalExitRootMap(bytes32 ) view returns(uint256)
func (_Gerl2 *Gerl2CallerSession) GlobalExitRootMap(arg0 [32]byte) (*big.Int, error) {
	return _Gerl2.Contract.GlobalExitRootMap(&_Gerl2.CallOpts, arg0)
}

// InjectedGERCount is a free data retrieval call binding the contract method 0x91750427.
//
// Solidity: function injectedGERCount() view returns(uint256)
func (_Gerl2 *Gerl2Caller) InjectedGERCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "injectedGERCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// InjectedGERCount is a free data retrieval call binding the contract method 0x91750427.
//
// Solidity: function injectedGERCount() view returns(uint256)
func (_Gerl2 *Gerl2Session) InjectedGERCount() (*big.Int, error) {
	return _Gerl2.Contract.InjectedGERCount(&_Gerl2.CallOpts)
}

// InjectedGERCount is a free data retrieval call binding the contract method 0x91750427.
//
// Solidity: function injectedGERCount() view returns(uint256)
func (_Gerl2 *Gerl2CallerSession) InjectedGERCount() (*big.Int, error) {
	return _Gerl2.Contract.InjectedGERCount(&_Gerl2.CallOpts)
}

// LastRollupExitRoot is a free data retrieval call binding the contract method 0x01fd9044.
//
// Solidity: function lastRollupExitRoot() view returns(bytes32)
func (_Gerl2 *Gerl2Caller) LastRollupExitRoot(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Gerl2.contract.Call(opts, &out, "lastRollupExitRoot")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// LastRollupExitRoot is a free data retrieval call binding the contract method 0x01fd9044.
//
// Solidity: function lastRollupExitRoot() view returns(bytes32)
func (_Gerl2 *Gerl2Session) LastRollupExitRoot() ([32]byte, error) {
	return _Gerl2.Contract.LastRollupExitRoot(&_Gerl2.CallOpts)
}

// LastRollupExitRoot is a free data retrieval call binding the contract method 0x01fd9044.
//
// Solidity: function lastRollupExitRoot() view returns(bytes32)
func (_Gerl2 *Gerl2CallerSession) LastRollupExitRoot() ([32]byte, error) {
	return _Gerl2.Contract.LastRollupExitRoot(&_Gerl2.CallOpts)
}

// InsertGlobalExitRoot is a paid mutator transaction binding the contract method 0x12da06b2.
//
// Solidity: function insertGlobalExitRoot(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2Transactor) InsertGlobalExitRoot(opts *bind.TransactOpts, _newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.contract.Transact(opts, "insertGlobalExitRoot", _newRoot)
}

// InsertGlobalExitRoot is a paid mutator transaction binding the contract method 0x12da06b2.
//
// Solidity: function insertGlobalExitRoot(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2Session) InsertGlobalExitRoot(_newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.InsertGlobalExitRoot(&_Gerl2.TransactOpts, _newRoot)
}

// InsertGlobalExitRoot is a paid mutator transaction binding the contract method 0x12da06b2.
//
// Solidity: function insertGlobalExitRoot(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2TransactorSession) InsertGlobalExitRoot(_newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.InsertGlobalExitRoot(&_Gerl2.TransactOpts, _newRoot)
}

// InsertGlobalExitRootCheat is a paid mutator transaction binding the contract method 0x6b37f64b.
//
// Solidity: function insertGlobalExitRoot_cheat(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2Transactor) InsertGlobalExitRootCheat(opts *bind.TransactOpts, _newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.contract.Transact(opts, "insertGlobalExitRoot_cheat", _newRoot)
}

// InsertGlobalExitRootCheat is a paid mutator transaction binding the contract method 0x6b37f64b.
//
// Solidity: function insertGlobalExitRoot_cheat(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2Session) InsertGlobalExitRootCheat(_newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.InsertGlobalExitRootCheat(&_Gerl2.TransactOpts, _newRoot)
}

// InsertGlobalExitRootCheat is a paid mutator transaction binding the contract method 0x6b37f64b.
//
// Solidity: function insertGlobalExitRoot_cheat(bytes32 _newRoot) returns()
func (_Gerl2 *Gerl2TransactorSession) InsertGlobalExitRootCheat(_newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.InsertGlobalExitRootCheat(&_Gerl2.TransactOpts, _newRoot)
}

// UpdateExitRoot is a paid mutator transaction binding the contract method 0x33d6247d.
//
// Solidity: function updateExitRoot(bytes32 newRoot) returns()
func (_Gerl2 *Gerl2Transactor) UpdateExitRoot(opts *bind.TransactOpts, newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.contract.Transact(opts, "updateExitRoot", newRoot)
}

// UpdateExitRoot is a paid mutator transaction binding the contract method 0x33d6247d.
//
// Solidity: function updateExitRoot(bytes32 newRoot) returns()
func (_Gerl2 *Gerl2Session) UpdateExitRoot(newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.UpdateExitRoot(&_Gerl2.TransactOpts, newRoot)
}

// UpdateExitRoot is a paid mutator transaction binding the contract method 0x33d6247d.
//
// Solidity: function updateExitRoot(bytes32 newRoot) returns()
func (_Gerl2 *Gerl2TransactorSession) UpdateExitRoot(newRoot [32]byte) (*types.Transaction, error) {
	return _Gerl2.Contract.UpdateExitRoot(&_Gerl2.TransactOpts, newRoot)
}

// Gerl2InsertGlobalExitRootIterator is returned from FilterInsertGlobalExitRoot and is used to iterate over the raw logs and unpacked data for InsertGlobalExitRoot events raised by the Gerl2 contract.
type Gerl2InsertGlobalExitRootIterator struct {
	Event *Gerl2InsertGlobalExitRoot // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *Gerl2InsertGlobalExitRootIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(Gerl2InsertGlobalExitRoot)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(Gerl2InsertGlobalExitRoot)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *Gerl2InsertGlobalExitRootIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *Gerl2InsertGlobalExitRootIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// Gerl2InsertGlobalExitRoot represents a InsertGlobalExitRoot event raised by the Gerl2 contract.
type Gerl2InsertGlobalExitRoot struct {
	NewGlobalExitRoot [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterInsertGlobalExitRoot is a free log retrieval operation binding the contract event 0xb1b866fe5fac68e8f1a4ab2520c7a6b493a954934bbd0f054bd91d6674a4c0d5.
//
// Solidity: event InsertGlobalExitRoot(bytes32 indexed newGlobalExitRoot)
func (_Gerl2 *Gerl2Filterer) FilterInsertGlobalExitRoot(opts *bind.FilterOpts, newGlobalExitRoot [][32]byte) (*Gerl2InsertGlobalExitRootIterator, error) {

	var newGlobalExitRootRule []interface{}
	for _, newGlobalExitRootItem := range newGlobalExitRoot {
		newGlobalExitRootRule = append(newGlobalExitRootRule, newGlobalExitRootItem)
	}

	logs, sub, err := _Gerl2.contract.FilterLogs(opts, "InsertGlobalExitRoot", newGlobalExitRootRule)
	if err != nil {
		return nil, err
	}
	return &Gerl2InsertGlobalExitRootIterator{contract: _Gerl2.contract, event: "InsertGlobalExitRoot", logs: logs, sub: sub}, nil
}

// WatchInsertGlobalExitRoot is a free log subscription operation binding the contract event 0xb1b866fe5fac68e8f1a4ab2520c7a6b493a954934bbd0f054bd91d6674a4c0d5.
//
// Solidity: event InsertGlobalExitRoot(bytes32 indexed newGlobalExitRoot)
func (_Gerl2 *Gerl2Filterer) WatchInsertGlobalExitRoot(opts *bind.WatchOpts, sink chan<- *Gerl2InsertGlobalExitRoot, newGlobalExitRoot [][32]byte) (event.Subscription, error) {

	var newGlobalExitRootRule []interface{}
	for _, newGlobalExitRootItem := range newGlobalExitRoot {
		newGlobalExitRootRule = append(newGlobalExitRootRule, newGlobalExitRootItem)
	}

	logs, sub, err := _Gerl2.contract.WatchLogs(opts, "InsertGlobalExitRoot", newGlobalExitRootRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(Gerl2InsertGlobalExitRoot)
				if err := _Gerl2.contract.UnpackLog(event, "InsertGlobalExitRoot", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInsertGlobalExitRoot is a log parse operation binding the contract event 0xb1b866fe5fac68e8f1a4ab2520c7a6b493a954934bbd0f054bd91d6674a4c0d5.
//
// Solidity: event InsertGlobalExitRoot(bytes32 indexed newGlobalExitRoot)
func (_Gerl2 *Gerl2Filterer) ParseInsertGlobalExitRoot(log types.Log) (*Gerl2InsertGlobalExitRoot, error) {
	event := new(Gerl2InsertGlobalExitRoot)
	if err := _Gerl2.contract.UnpackLog(event, "InsertGlobalExitRoot", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
