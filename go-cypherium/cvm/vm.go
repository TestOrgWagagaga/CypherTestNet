package cvm

import (
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	//	"os"
	"path"

	"github.com/cypherium/CypherTestNet/go-cypherium/accounts/abi"
	"github.com/cypherium/CypherTestNet/go-cypherium/common"
	"github.com/orcaman/concurrent-map"
)

const pc_MaxCount = 20000000

type SystemSettings map[string]string

func (this SystemSettings) SetSystemSetting(key string, value string) {
	this[key] = value
}

func (this SystemSettings) GetSystemSetting(key string) string {
	return this[key]
}

type CVM struct {
	SystemSettings
	*ExecutionEngine
	*MethodArea
	*Heap
	*OS
	*LoggerFactory
	*Logger

	Classloader JavaLangClassLoader

	memCode      []byte
	contractPath string
	In           interface{}
	totalPc      int
	startCount   bool
}

var VM_CurrentPath = ""
var VM_WG = &sync.WaitGroup{}

var VM = NewVM()

func NewVM() *CVM {
	if VM_CurrentPath == "" {
		VM_CurrentPath, _ = filepath.Abs(".")
		VM_CurrentPath = strings.Replace(VM_CurrentPath, "\\", "/", -1)
	}

	vm := &CVM{}
	vm.Classloader = NULL
	vm.SystemSettings = map[string]string{
		"log.base":              path.Join(VM_CurrentPath, "log"),
		"log.level.threads":     strconv.Itoa(WARN),
		"log.level.thread":      strconv.Itoa(WARN),
		"log.level.classloader": strconv.Itoa(WARN),
		"log.level.io":          strconv.Itoa(WARN),
		"log.level.misc":        strconv.Itoa(WARN),

		"classpath.system":      path.Join(VM_CurrentPath, "jdk/classes"),
		"classpath.extension":   "",
		"classpath.application": "",
	}

	vm.LoggerFactory = &LoggerFactory{}

	return vm
}

// Before vm initialization, all lot of system settings can be set.
func (this *CVM) Init() {
	natives := make(map[string]reflect.Value)

	threadsLogLevel, _ := strconv.Atoi(this.GetSystemSetting("log.level.threads"))
	ioLogLevel, _ := strconv.Atoi(this.GetSystemSetting("log.level.io"))
	this.ExecutionEngine = &ExecutionEngine{
		make([]Instruction, JVM_OPC_MAX+1),
		natives,
		cmap.New(),
		this.NewLogger("threads", threadsLogLevel, "threads.log"),
		this.NewLogger("io", ioLogLevel, "io.log")}
	this.RegisterInstructions()
	this.RegisterNatives()

	this.Heap = &Heap{}

	classloaderLogLevel, _ := strconv.Atoi(this.GetSystemSetting("log.level.classloader"))
	systemClasspath := VM.GetSystemSetting("classpath.system")
	this.MethodArea = &MethodArea{
		make(map[NL]*Class),
		make(map[NL]*Class),
		make(map[string]JavaLangString),
		&BootstrapClassLoader{
			NewClassPath(systemClasspath),
			this.NewLogger("classloader", classloaderLogLevel, "classloader.log"),
		},
	}

	this.OS = &OS{}

	miscLogLevel, _ := strconv.Atoi(this.GetSystemSetting("log.level.misc"))
	this.Logger = this.LoggerFactory.NewLogger("misc", miscLogLevel, "misc.log")
}

func (this *CVM) StarMain(memCode []byte, className string) {
	if this.Classloader == NULL {
		this.Init()
	}
	VM.Heap = &Heap{}
	VM.memCode = memCode
	VM.contractPath = VM_CurrentPath + "/" + className + ".class"

	// bootstrap thread don't run in a new go routine, just in Go startup routine
	VM.RunBootstrapThread(
		func() {

			if VM.Classloader == NULL {
				VM.InvokeMethodOf("java/lang/System", "initializeSystemClass", "()V")
				// Use AppClassLoader to load initial class
				VM.Classloader = VM.InvokeMethodOf("java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;").(JavaLangClassLoader)
			}
			initialClass := VM.createClass(className, VM.Classloader, TRIGGER_BY_ACCESS_MEMBER)
			method := initialClass.FindMethod("main", "([Ljava/lang/String;)V")
			if method == nil {
				return
			}

			VM.NewThread("main",
				func() {
					VM.InvokeMethod(method)
				},
				func() {
					VM.exitDaemonThreads()
				}).start()
		})

	VM_WG.Wait()
}

func (this *CVM) StartFunction(memCode []byte, className, methodName string, javaArgs []byte) string {
	if this.Classloader == NULL {
		this.Init()
	}

	VM.Heap = &Heap{}
	isRunningOK := false
	VM.memCode = memCode
	VM.contractPath = VM_CurrentPath + "/" + className + ".class"

	i := strings.Index(methodName, "(")
	if i < 1 {
		return ""
	}
	desc := methodName[i+1 : len(methodName)-1]
	descLists := strings.Split(desc, ",")

	values, methodDesc, err := VM.getInputArgsValue(descLists, javaArgs)
	if err != nil {
		return ""
	}
	methodName = methodName[:i]
	retValue := ""
	// bootstrap thread don't run in a new go routine, just in Go startup routine
	VM.RunBootstrapThread(func() {
		if VM.Classloader == NULL {
			VM.InvokeMethodOf("java/lang/System", "initializeSystemClass", "()V")
			VM.Classloader = VM.InvokeMethodOf("java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;").(JavaLangClassLoader)
		}
		initialClass := VM.createClass(className, VM.Classloader, TRIGGER_BY_ACCESS_MEMBER)
		method := initialClass.FindMethod(methodName, methodDesc)
		if method == nil {
			return
		}

		// initial a thread
		VM.NewThread("main",
			func() {
				params, err := VM.covertToJavaParams(descLists, values)
				if err != nil {
					return
				}
				VM.startCount = true
				VM.totalPc = 0
				ret := VM.InvokeMethod(method, params...)
				isRunningOK = true
				VM.startCount = false
				switch ret.(type) {
				case JavaLangString:
					p := ret.(JavaLangString)
					if !p.IsNull() {
						retValue = p.ToNativeString()
					}
				default:
					fmt.Println(ret)
				}
			},
			func() {
				VM.exitDaemonThreads()
			}).start()
	})

	VM_WG.Wait()
	VM.startCount = false
	if !isRunningOK {
		this.Classloader = NULL //reinit and reload for next time
	}

	return retValue
}

func (this *CVM) getInputArgsValue(typeList []string, encb []byte) ([]interface{}, string, error) {

	desc := "("
	s := "["
	for _, stype := range typeList {
		s += fmt.Sprintf(`{"type": "%s"},`, stype)

		if strings.Index(stype, "uint") == 0 {
			desc += "J"
		} else if strings.Index(stype, "int") == 0 {
			desc += "J"
		} else if strings.Index(stype, "fixed") == 0 {
			desc += "D"
		} else if strings.Index(stype, "bytes") == 0 {
			desc += "Ljava/lang/String;"
		} else if strings.Index(stype, "address") == 0 {
			desc += "Ljava/lang/String;"
		} else if strings.Index(stype, "string") == 0 {
			desc += "Ljava/lang/String;"
		} else if strings.Index(stype, "bool") == 0 {
			desc += "Z"
		}
	}

	s = s[:len(s)-1] + "]"
	desc += ")Ljava/lang/String;"

	def := fmt.Sprintf(`[{ "name" : "method", "outputs": %s }]`, s)
	abi, err := abi.JSON(strings.NewReader(def))
	if err != nil {
		return nil, "", err
	}
	values, err1 := abi.Methods["method"].Outputs.UnpackValues(encb)

	return values, desc, err1
}

func (this *CVM) covertToJavaParams(typeList []string, values []interface{}) ([]Value, error) {

	n := len(values)
	if n != len(typeList) {
		return nil, fmt.Errorf("typeList not correspond with values")
	}
	params := make([]Value, n)
	for i, stype := range typeList {
		v := values[i]
		if strings.Index(stype, "uint") == 0 {
			a := v.(*big.Int)
			params[i] = Long(a.Int64())
		} else if strings.Index(stype, "int") == 0 {
			a := v.(*big.Int)
			params[i] = Long(a.Int64())
		} else if strings.Index(stype, "fixed") == 0 {
			//b := v.(big.Float)
			//params[i] = Double(v.Float())
			return nil, fmt.Errorf("Type conversion error! not support fixed")
		} else if strings.Index(stype, "address") == 0 {
			a := v.(common.Address)
			s := a.String()
			params[i] = VM.NewJavaLangString(s)
		} else if strings.Index(stype, "bytes") == 0 {
			a := v.([]byte)
			params[i] = VM.NewJavaLangString(string(a))
		} else if strings.Index(stype, "string") == 0 {
			a := v.([]byte)
			params[i] = VM.NewJavaLangString(string(a))
		} else if strings.Index(stype, "bool") == 0 {
			a := v.(bool)
			if a {
				params[i] = Boolean(1)
			} else {
				params[i] = Boolean(0)
			}
		} else {
			return nil, fmt.Errorf("Type conversion error!")
		}
	}

	return params, nil
}

func CVM_init(registerNative func()) {
	if VM.Classloader != NULL {
		return
	}

	VM.Init()
	registerNative()
	VM.RunBootstrapThread(
		func() {
			VM.InvokeMethodOf("java/lang/System", "initializeSystemClass", "()V")
			VM.Classloader = VM.InvokeMethodOf("java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;").(JavaLangClassLoader)
		})

	VM_WG.Wait()
}
