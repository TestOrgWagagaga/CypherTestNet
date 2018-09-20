package cvm

import (
	"reflect"
)

type NativeMethodRegistry map[string]reflect.Value

func (this NativeMethodRegistry) RegisterNative(qualifier string, function interface{}) {
	this[qualifier] = reflect.ValueOf(function)
}

func (this NativeMethodRegistry) unregister(qualifier string, function interface{}) {
	delete(this, qualifier)
}

func (this NativeMethodRegistry) FindNative(qualifier string) (reflect.Value, bool) {
	fun, found := this[qualifier]
	return fun, found
}

func (this NativeMethodRegistry) RegisterNatives() {
	register_java_lang_System()
	register_java_lang_Object()
	register_java_lang_Class()
	register_java_lang_ClassLoader()
	register_java_lang_Package()

	register_java_lang_String()

	register_java_lang_Thread()
	register_java_lang_Throwable()
	register_java_lang_Runtime()
	register_java_security_AccessController()
	register_java_lang_reflect_Array()

	register_java_lang_math()
	register_sun__()
	register_java_io_()
	register_java_util_()

}
