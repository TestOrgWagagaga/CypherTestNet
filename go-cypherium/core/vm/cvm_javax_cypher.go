package vm

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/cypherium/CypherTestNet/go-cypherium/common"
	"github.com/cypherium/CypherTestNet/go-cypherium/cvm"
)

func register_javax_cypher_cypnet() {

	cvm.VM.RegisterNative("javax/cypher/cypnet.SetTokenInfo(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)Z", JDK_javax_cypher_cypnet_SetTokenInfo)
	cvm.VM.RegisterNative("javax/cypher/cypnet.BalanceOf(Ljava/lang/String;)J", JDK_javax_cypher_cypnet_BalanceOf)
	cvm.VM.RegisterNative("javax/cypher/cypnet.ChangeBalance(Ljava/lang/String;J)Z", JDK_javax_cypher_cypnet_ChangeBalance)
	cvm.VM.RegisterNative("javax/cypher/cypnet.Transfer(Ljava/lang/String;Ljava/lang/String;J)Z", JDK_javax_cypher_cypnet_Transfer)
	cvm.VM.RegisterNative("javax/cypher/cypnet.GetState(Ljava/lang/String;)Ljava/lang/String;", JDK_javax_cypher_cypnet_GetState)
	cvm.VM.RegisterNative("javax/cypher/cypnet.SetState(Ljava/lang/String;Ljava/lang/String;)Z", JDK_javax_cypher_cypnet_SetState)
	cvm.VM.RegisterNative("javax/cypher/cypnet.GetAddress(Ljava/lang/String;)Ljava/lang/String;", JDK_javax_cypher_cypnet_GetAddress)
}

func JDK_javax_cypher_cypnet_SetTokenInfo(symbol cvm.JavaLangString, name cvm.JavaLangString, totalSupply cvm.Long, owner cvm.JavaLangString) cvm.Boolean {
	JDK_setContractValue("symbol()", symbol.ToNativeString())
	JDK_setContractValue("name()", name.ToNativeString())

	addr := JDK_getCheckedAddress(owner.ToNativeString())
	if addr == "" {
		addr = JDK_getCheckedAddress("caller")
	}
	JDK_setContractValue("owner()", addr)

	JDK_setContractValue("totalSupply()", int64(totalSupply))

	return cvm.TRUE
}

func JDK_javax_cypher_cypnet_BalanceOf(address cvm.JavaLangString) cvm.Long {
	hashv, err := JDK_getContractBalance(address.ToNativeString())
	if err != nil {
		return cvm.Long(0)
	}
	v := hashv.Big().Int64()
	return cvm.Long(v)
}

func JDK_javax_cypher_cypnet_ChangeBalance(address cvm.JavaLangString, value cvm.Long) cvm.Boolean {
	JDK_setContractBalance(address.ToNativeString(), int64(value))

	return cvm.TRUE
}

func JDK_javax_cypher_cypnet_Transfer(sFrom, sTo cvm.JavaLangString, value cvm.Long) cvm.Boolean {
	sfrom := sFrom.ToNativeString()
	sto := sTo.ToNativeString()

	hashv, err := JDK_getContractBalance(sfrom)
	if err != nil {
		return cvm.FALSE
	}
	fromV := hashv.Big().Int64()
	if fromV <= 0 {
		return cvm.FALSE
	}

	hashv, err = JDK_getContractBalance(sto)
	if err != nil {
		return cvm.FALSE
	}
	toV := hashv.Big().Int64()
	if toV < 0 {
		return cvm.FALSE
	}

	fromV = fromV - int64(value)
	if fromV < 0 {
		return cvm.FALSE
	}

	toV = toV + int64(value)

	JDK_setContractBalance(sfrom, fromV)
	JDK_setContractBalance(sto, toV)

	return cvm.TRUE
}

func JDK_javax_cypher_cypnet_GetState(key cvm.JavaLangString) cvm.JavaLangString {
	skey := key.ToNativeString()
	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB
	v := s.GetState(in.contract.Address(), common.BytesToHash([]byte("@"+skey)))
	if v == (common.Hash{}) {
		return cvm.NULL
	}
	sValue := string(VM_GetSBytes(v.Bytes(), -1))
	return cvm.VM.NewJavaLangString(sValue)
}

func JDK_javax_cypher_cypnet_SetState(key cvm.JavaLangString, value cvm.JavaLangString) cvm.Boolean {
	skey := key.ToNativeString()
	svalue := value.ToNativeString()

	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB

	hashV := common.BytesToHash([]byte(svalue))
	s.SetState(in.contract.Address(), common.BytesToHash([]byte("@"+skey)), hashV)

	return cvm.TRUE
}

func JDK_javax_cypher_cypnet_GetAddress(address cvm.JavaLangString) cvm.JavaLangString {
	addrType := address.ToNativeString()
	addr := addrType
	switch addrType {
	case "self":
		in := cvm.VM.In.(*JVMInterpreter)
		addr = strings.ToUpper(in.contractAddr)
	case "caller":
		in := cvm.VM.In.(*JVMInterpreter)
		addr = strings.ToUpper(in.callerAddress)
		//case "owner"
	}

	return cvm.VM.NewJavaLangString(addr)
}

//----------------------------------------------------------------------------------------------

func JDK_getContractValue(key string) common.Hash {
	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB
	symbolKey := []byte(in.contractAddr + key)
	v := s.GetState(in.contract.Address(), common.BytesToHash(symbolKey))
	return v
}

func JDK_setContractValue(key string, value interface{}) bool {
	var hashV common.Hash
	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB
	symbolKey := []byte(in.contractAddr + key)

	switch value.(type) {
	case int:
		hashV = common.BigToHash(new(big.Int).SetInt64(int64(value.(int))))
	case int64:
		hashV = common.BigToHash(new(big.Int).SetInt64(value.(int64)))
	case string:
		hashV = common.BytesToHash([]byte(value.(string)))
	}

	s.SetState(in.contract.Address(), common.BytesToHash(symbolKey), hashV)

	return true
}

func JDK_getContractBalance(addr string) (common.Hash, error) {
	addr = JDK_getCheckedAddress(addr)
	if addr == "" {
		return common.Hash{}, fmt.Errorf("Address is invalidate!")
	}

	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB
	v := s.GetState(in.contract.Address(), common.BytesToHash([]byte(addr+"_@BalanceOf")))
	return v, nil
}

func JDK_setContractBalance(addr string, v int64) bool {
	addr = JDK_getCheckedAddress(addr)
	if addr == "" {
		return false
	}

	in := cvm.VM.In.(*JVMInterpreter)
	s := in.evm.StateDB

	s.SetState(in.contract.Address(), common.BytesToHash([]byte(addr+"_@BalanceOf")), common.BigToHash(new(big.Int).SetInt64(v)))
	return true
}

func JDK_getCheckedAddress(addr string) string {
	switch addr {
	case "self":
		return strings.ToUpper(cvm.VM.In.(*JVMInterpreter).contractAddr)
	case "caller":
		return strings.ToUpper(cvm.VM.In.(*JVMInterpreter).callerAddress)
		//case "owner"
	}

	if len(addr) != 42 { //？？ find the constant value
		return ""
	}
	addr = strings.ToUpper(addr)
	if addr[0] != '0' && addr[1] != 'X' {
		return ""
	}

	return addr
}
