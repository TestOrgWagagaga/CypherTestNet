package cvm
import "time"

func register_java_util_() {
	VM.RegisterNative("java/util/concurrent/atomic/AtomicLong.VMSupportsCS8()Z", JDK_java_util_concurrent_atomic_AtomicLong_VMSupportsCS8)

	VM.RegisterNative("java/util/zip/ZipFile.initIDs()V", JDK_java_util_zip_ZipFile_initIDs)

	VM.RegisterNative("java/util/TimeZone.getSystemTimeZoneID(Ljava/lang/String;)Ljava/lang/String;", JDK_java_util_TimeZone_getSystemTimeZoneID)
	
}

func JDK_java_util_concurrent_atomic_AtomicLong_VMSupportsCS8() Boolean {
	return TRUE
}

func JDK_java_util_zip_ZipFile_initIDs() {
	//DO NOTHING
}

func JDK_java_util_TimeZone_getSystemTimeZoneID(javaHome JavaLangString) JavaLangString {
	loc := time.Local
	return VM.NewJavaLangString(loc.String())
}
