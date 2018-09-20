package cvm

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	//	"os"
	"path"

	"github.com/cypherium_private/go-cypherium/common"
	"github.com/orcaman/concurrent-map"
)

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
	memCode      []byte
	contractPath string
	In           interface{}
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
	VM.memCode = memCode
	VM.contractPath = VM_CurrentPath + "/" + className + ".class"

	// bootstrap thread don't run in a new go routine, just in Go startup routine
	VM.RunBootstrapThread(
		func() {
			VM.InvokeMethodOf("java/lang/System", "initializeSystemClass", "()V")
			// Use AppClassLoader to load initial class
			systemClassLoaderObject := VM.InvokeMethodOf("java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;").(JavaLangClassLoader)
			initialClass := VM.createClass(className, systemClassLoaderObject, TRIGGER_BY_ACCESS_MEMBER)
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

func (this *CVM) StartFunction(memCode []byte, className, methodName string, javaArgs [][]byte) {
	VM.memCode = memCode
	VM.contractPath = VM_CurrentPath + "/" + className + ".class"

	i := strings.Index(methodName, "(")
	if i < 1 {
		return
	}
	desc := methodName[i+1 : len(methodName)-1]
	methodName = methodName[:i]

	// bootstrap thread don't run in a new go routine, just in Go startup routine
	VM.RunBootstrapThread(func() {
		VM.InvokeMethodOf("java/lang/System", "initializeSystemClass", "()V")

		// Use AppClassLoader to load initial class
		systemClassLoaderObject := VM.InvokeMethodOf("java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;").(JavaLangClassLoader)
		initialClass := VM.createClass(className, systemClassLoaderObject, TRIGGER_BY_ACCESS_MEMBER)
		methodDesc, _, err := VM.getParaList(desc, nil)
		if err != nil {
			return
		}
		method := initialClass.FindMethod(methodName, methodDesc)
		if method == nil {
			return
		}

		// initial a thread
		VM.NewThread("main",
			func() {
				_, params, err := VM.getParaList(desc, javaArgs)
				if err != nil {
					return
				}
				VM.InvokeMethod(method, params...)
			},
			func() {
				VM.exitDaemonThreads()
			}).start()
	})

	VM_WG.Wait()
}

func (this *CVM) getParaList(argDesc string, javaArgs [][]byte) (string, []Value, error) {
	//methodDesc = VM_GetDescFromMethod(methodName)
	desc := "("
	descLists := strings.Split(argDesc, ",")
	n := len(descLists)
	if n == 0 {
		return "", nil, nil
	}

	params := make([]Value, n)
	for i, stype := range descLists {
		if strings.Index(stype, "uint") == 0 {
			desc += "J"
			if javaArgs != nil && javaArgs[i] != nil {
				s := common.Bytes2Hex(javaArgs[i])
				v, err := strconv.ParseInt(s, 16, 64)
				if err != nil {
					return "", nil, fmt.Errorf("Type uint conversion error.")
				}
				params[i] = Long(v)
			}
		} else if strings.Index(stype, "int") == 0 {
			desc += "J"
			if javaArgs != nil && javaArgs[i] != nil {
				s := common.Bytes2Hex(javaArgs[i])
				v, err := strconv.ParseInt(s, 16, 64)
				if err != nil {
					return "", nil, fmt.Errorf("Type int conversion error.")
				}
				params[i] = Long(v)
			}
		} else if strings.Index(stype, "fixed") == 0 {
			desc += "D"
			if javaArgs != nil && javaArgs[i] != nil {
				s := common.Bytes2Hex(javaArgs[i])
				v, err := strconv.ParseFloat(s, 64)
				if err != nil {
					return "", nil, fmt.Errorf("Type fixed conversion error.")
				}
				params[i] = Double(v)
			}
		} else if strings.Index(stype, "bytes") == 0 {
			desc += "D"
			if javaArgs != nil && javaArgs[i] != nil {
				s := common.Bytes2Hex(javaArgs[i])
				v, err := strconv.ParseFloat(s, 64)
				if err != nil {
					return "", nil, fmt.Errorf("Type bytes conversion error.")
				}
				params[i] = Double(v)
			}
		} else {
			switch stype {
			case "address":
				desc += "Ljava/lang/String;"
				if javaArgs != nil && javaArgs[i] != nil {
					s := common.Bytes2Hex(javaArgs[i])
					if !(s[0] == '0' && (s[0] == 'x' || s[0] == 'X')) {
						s = "0X" + s
					}
					params[i] = VM.NewJavaLangString(strings.ToUpper(s))
				}
			case "bool":
				desc += "Z"
				if javaArgs != nil && javaArgs[i] != nil {
					params[i] = Boolean(javaArgs[i][0])
				}
			case "string":
				desc += "Ljava/lang/String;"
				if javaArgs != nil && javaArgs[i] != nil {
					params[i] = VM.NewJavaLangString(string(javaArgs[i]))
				}
			}
		}
	}

	desc += ")Ljava/lang/String;"

	return desc, params, nil
}
