package vm

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cypherium/CypherTestNet/go-cypherium/accounts/abi"
	"github.com/cypherium/CypherTestNet/go-cypherium/common"
	"github.com/cypherium/CypherTestNet/go-cypherium/cvm"
	"github.com/cypherium/CypherTestNet/go-cypherium/params"
)

var is_cvm_Initialized = false

// Config are the configuration options for the Interpreter
type ConfigJVM struct {
	// Debug enabled debugging Interpreter options
	Debug bool
	// Tracer is the op code logger
	Tracer Tracer
	// NoRecursion disabled Interpreter call, callcode,
	// delegate call and create.
	NoRecursion bool
	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool
	// JumpTable contains the EVM instruction table. This
	// may be left uninitialised and will be set to the default
	// table.
	//??JumpTable [256]operation
}

// EVMInterpreter represents an EVM interpreter
type JVMInterpreter struct {
	evm      *EVM
	cfg      Config
	gasTable params.GasTable

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse

	cvm           *cvm.CVM
	contract      *Contract
	contractAddr  string
	callerAddress string
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewJVMInterpreter(evm *EVM, cfg Config) *JVMInterpreter {
	if !is_cvm_Initialized {
		is_cvm_Initialized = true
	}

	return &JVMInterpreter{
		evm:      evm,
		cfg:      cfg,
		gasTable: evm.ChainConfig().GasTable(evm.BlockNumber),
		cvm:      cvm.VM,
	}
}

func (in *JVMInterpreter) Run(contract *Contract, input []byte) (ret []byte, err error) {
	const NP = 32
	n := len(input)
	methodName := ""
	methodArgs := []byte{}

	if n >= (4+NP) && input[0] == 0xfe && input[1] == 0xfe && input[2] == 0xfe && input[3] == 0xfe {
		i := 4
		methodName = string(VM_GetSBytes(input[i:], NP))
		if n > i+NP {
			methodArgs = input[i+NP:]
		}
	}

	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}
	contract.Input = input
	in.contract = contract
	in.contractAddr = contract.Address().String()
	in.callerAddress = contract.Caller().String()

	in.cvm.In = in

	//计算class的 运算量、内存、和存储

	//javaCode, err := bitutil.DecompressBytes(contract.Code, 846)
	//javaCode := contract.Code //make([]byte, len(contract.Code)*2)
	//javaCode, err := hexutil.Decode(string(contract.Code))
	//rlp.DecodeBytes(contract.Code, javaCode)
	//in.evm.Context, in.evm.StateDB,
	//res, err := cvm.StartVM( contract.Code, "", methodName,  methodArgs)

	res, err := in.startVM(contract.Code, "", methodName, methodArgs)
	fmt.Println("in.startVM end.")
	//in.startVM(contract.Code, "", methodName,  methodArgs)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	if res == nil && methodName == "" {
		return contract.Code, nil
	}

	//in.returnData = resBytes
	/*
		switch {
		case err == errExecutionReverted:
			return res, errExecutionReverted
		case err != nil:
			return nil, err
		}
	*/
	return res, nil
}

// CanRun tells if the contract, passed as an argument, can be
// run by the current interpreter.
func (in *JVMInterpreter) CanRun(code []byte) bool {
	//try to find java magic
	if len(code) > 8 && code[0] == 0xCA && code[1] == 0xFE && code[2] == 0xBA && code[3] == 0xBE {
		return true
	}
	return false
}

// IsReadOnly reports if the interpreter is in read only mode.
func (in *JVMInterpreter) IsReadOnly() bool {
	return in.readOnly
}

// SetReadOnly sets (or unsets) read only mode in the interpreter.
func (in *JVMInterpreter) SetReadOnly(ro bool) {
	in.readOnly = ro
}

func (in *JVMInterpreter) startVM(memCode []byte, className, methodName string, javaArgs []byte) ([]byte, error) {
	argsLen := len(javaArgs)

	if className == "" {
		className = "cypherium_@Contract"
		if methodName == "" { //main,create contract
			in.cvm.StarMain(memCode, className, register_javax_cypher_cypnet)
			return memCode, nil

		} else if argsLen == 0 {
			if methodName == "owner()" || methodName == "symbol()" || methodName == "name()" || methodName == "totalSupply()" {
				res := JDK_getContractValue(methodName)
				if methodName == "totalSupply()" {
					return res.Bytes(), nil
				}
				s := VM_HashByteToRes(res.Bytes())
				//fmt.Println(s)
				return s, nil
			} else if methodName == "decimals()" {
				s, err := VM_PackToRes("uint32", uint32(8))
				return s, err
				/*
					decimals := []byte{8} //the float fixed = 8
					s := VM_HashByteToRes(decimals)
					//fmt.Println(s)
					return s, nil
				*/
			}
		} else { //argsLen > 0
			if methodName == "transfer(address,uint256)" && argsLen == 64 { //32*2 call Transfer in java class
				methodName = "Transfer(address,uint256)"
				//methodDesc = "(Ljava/lang/String;J)Ljava/lang/String;"

			} else if methodName == "balanceOf(address)" {
				if argsLen == 0 {
					return nil, fmt.Errorf("balanceOf: not found address")
				}
				s := common.Bytes2Hex(VM_GetSBytes(javaArgs, -1))
				hashv, err := JDK_getContractBalance(s)
				if err != nil {
					return nil, err
				}
				return hashv.Bytes(), nil
			}
		}
	} else {
		fmt.Println("Support other class names in the future!")
	}

	ret := in.cvm.StartFunction(memCode, className, methodName, javaArgs)
	if ret == "" {
		return nil, nil
	}
	s, err := VM_PackToRes("string", reflect.ValueOf(ret)) //only return string
	return s, err

	//return nil, nil
}

func VM_PackToRes(stype string, v interface{}) ([]byte, error) {
	def := fmt.Sprintf(`[{"type":"function","name":"return","inputs":[{"type": "%s" }] }]`, stype)
	abi, _ := abi.JSON(strings.NewReader(def))
	return abi.PackArgs("return", v)
}

func VM_HashByteToRes(inBuf []byte) []byte {
	res := []byte{}
	n := len(inBuf)
	i := 0
	for inBuf[i] == 0 {
		i++
	}

	zeroBuf := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} //先简单一点
	res = append(res, zeroBuf...)
	res[31] = 32

	res = append(res, zeroBuf...)
	res[63] = byte(n - i) //先简单一点，假设长度小于32,大于32要做复杂考虑

	res = append(res, inBuf[i:]...)
	res = append(res, zeroBuf[32-i:]...) //后面补0

	return res
}

func VM_GetSBytes(b []byte, n int) []byte {
	if n <= 0 {
		n = len(b)
	}

	if b[0] != 0 { //"string"
		i := 0
		for ; i < n; i++ {
			if b[i] == 0 {
				break
			}
		}
		return b[:i]
	} else {
		i := 0
		for ; i < n; i++ {
			if b[i] != 0 {
				break
			}
		}
		return b[i:n]
	}

	return nil
}
