package cvm

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const m_spath = "E:/golang/src/JVM/HelloWorld.class"

func JDK_java_io_MemCheck() bool {
	return true
}

func JDK_java_io_MemRead(buf []byte, offset int64) (int, error) {
	/*
		file, _ := os.Open(m_spath)
		file.Seek(offset, 0)
		nsize, err1 := file.Read(buf)
		return nsize, err1
	*/
	nsize := len(buf)
	copy(buf, VM.memCode[offset:])
	return nsize, nil

}

func JDK_java_io_MemGetLength() int64 {
	return int64(len(VM.memCode))
	/*
		fileInfo, err := os.Stat(m_spath)
		if err == nil {
			return fileInfo.Size()
		}

		return 0
	*/
}

//----------------------------------------------------------------------------------------------------
func register_java_io_() {
	VM.RegisterNative("java/io/FileDescriptor.initIDs()V", JDK_java_io_FileDescriptor_initIDs)

	VM.RegisterNative("java/io/FileInputStream.initIDs()V", JDK_java_io_FileInputStream_initIDs)
	VM.RegisterNative("java/io/FileInputStream.open0(Ljava/lang/String;)V", JDK_java_io_FileInputStream_open0)
	VM.RegisterNative("java/io/FileInputStream.readBytes([BII)I", JDK_java_io_FileInputStream_readBytes)
	VM.RegisterNative("java/io/FileInputStream.close0()V", JDK_java_io_FileInputStream_close0)

	VM.RegisterNative("java/io/FileOutputStream.initIDs()V", JDK_java_io_FileOutputStream_initIDs)
	VM.RegisterNative("java/io/FileOutputStream.writeBytes([BIIZ)V", JDK_java_io_FileOutputStream_writeBytes)

	VM.RegisterNative("java/io/UnixFileSystem.initIDs()V", JDK_java_io_UnixFileSystem_initIDs)
	VM.RegisterNative("java/io/UnixFileSystem.canonicalize0(Ljava/lang/String;)Ljava/lang/String;", JDK_java_io_UnixFileSystem_canonicalize0)
	VM.RegisterNative("java/io/UnixFileSystem.getBooleanAttributes0(Ljava/io/File;)I", JDK_java_io_UnixFileSystem_getBooleanAttributes0)
	VM.RegisterNative("java/io/UnixFileSystem.getLength(Ljava/io/File;)J", JDK_java_io_UnixFileSystem_getLength)
}

// private static void registers()
func JDK_java_io_FileDescriptor_initIDs() {}

//----------------------------------------------------------------------------------------------

func JDK_java_io_FileInputStream_initIDs() {
	// TODO
}

func JDK_java_io_FileInputStream_open0(this Reference, name JavaLangString) {
	path := name.ToNativeString()
	if path == VM.contractPath {
		if !JDK_java_io_MemCheck() {
			VM.Throw("java/io/IOException", "Cannot open file: %s", path)
		}
		return
	}

	_, error := os.Open(path)
	if error != nil {
		VM.Throw("java/io/IOException", "Cannot open file: %s", path)
	}
}

func JDK_java_io_FileInputStream_readBytes(this Reference, byteArr ArrayRef, offset Int, length Int) Int {

	var file *os.File

	fileDescriptor := this.GetInstanceVariableByName("fd", "Ljava/io/FileDescriptor;").(Reference)
	path := this.GetInstanceVariableByName("path", "Ljava/lang/String;").(JavaLangString)
	spath := path.ToNativeString()
	isMemPath := (spath == VM.contractPath)

	if !path.IsNull() && !isMemPath {
		f, err := os.Open(spath)
		if err != nil {
			VM.Throw("java/io/IOException", "Cannot open file: %s", spath)
		}
		file = f
	} else if !fileDescriptor.IsNull() {
		fd := fileDescriptor.GetInstanceVariableByName("fd", "I").(Int)
		switch fd {
		case 0:
			file = os.Stdin
		case 1:
			file = os.Stdout
		case 2:
			file = os.Stderr
		default:
			file = os.NewFile(uintptr(fd), "")
		}
	}

	if file == nil && !isMemPath {
		VM.Throw("java/io/IOException", "File cannot open")
	}

	err := error(nil)
	nsize := 0
	bytes := make([]byte, length)
	if isMemPath {
		nsize, err = JDK_java_io_MemRead(bytes, int64(offset))
	} else {
		file.Seek(int64(offset), 0)
		nsize, err = file.Read(bytes)
		VM.ExecutionEngine.ioLogger.Info("🅹 �?%s - buffer size: %d, offset: %d, len: %d, actual read: %d \n", file.Name(), byteArr.ArrayLength(), offset, length, nsize)
	}

	if err == nil || nsize == int(length) {
		for i := 0; i < int(length); i++ {
			byteArr.SetArrayElement(offset+Int(i), Byte(bytes[i]))
		}
		return Int(nsize)
	}

	VM.Throw("java/io/IOException", err.Error())
	return -1
}

func JDK_java_io_FileInputStream_close0(this Reference) {
	var file *os.File

	fileDescriptor := this.GetInstanceVariableByName("fd", "Ljava/io/FileDescriptor;").(Reference)
	path := this.GetInstanceVariableByName("path", "Ljava/lang/String;").(JavaLangString)
	spath := path.ToNativeString()
	if spath == VM.contractPath {
		return
	}

	if !fileDescriptor.IsNull() {
		fd := fileDescriptor.GetInstanceVariableByName("fd", "I").(Int)
		switch fd {
		case 0:
			file = os.Stdin
		case 1:
			file = os.Stdout
		case 2:
			file = os.Stderr
		}
	} else {
		f, err := os.Open(spath)
		if err != nil {
			VM.Throw("java/io/IOException", "Cannot open file: %s", spath)
		}
		file = f
	}
	if file != nil {
		err := file.Close()
		if err != nil {
			VM.Throw("java/io/IOException", "Cannot close file: %s", path)
		}
	}
}

//----------------------------------------------------------------------------------------------
func JDK_java_io_FileOutputStream_initIDs() {
	// TODO
}

func JDK_java_io_FileOutputStream_writeBytes(this Reference, byteArr ArrayRef, offset Int, length Int, append Boolean) {
	var file *os.File

	fileDescriptor := this.GetInstanceVariableByName("fd", "Ljava/io/FileDescriptor;").(Reference)
	path := this.GetInstanceVariableByName("path", "Ljava/lang/String;").(JavaLangString)

	if !path.IsNull() {
		f, err := os.Open(path.ToNativeString())
		if err != nil {
			VM.Throw("java/lang/IOException", "Cannot open file: %s", path.ToNativeString())
		}
		file = f
	} else if !fileDescriptor.IsNull() {
		fd := fileDescriptor.GetInstanceVariableByName("fd", "I").(Int)
		switch fd {
		case 0:
			file = os.Stdin
		case 1:
			file = os.Stdout
		case 2:
			file = os.Stderr
		default:
			file = os.NewFile(uintptr(fd), "")
		}
	}

	if file == nil {
		VM.Throw("java/lang/IOException", "File cannot open")
	}

	if append.IsTrue() {
		file.Chmod(os.ModeAppend)
	}

	bytes := make([]byte, byteArr.ArrayLength())
	for i := 0; i < int(byteArr.ArrayLength()); i++ {
		bytes[i] = byte(int8(byteArr.GetArrayElement(Int(i)).(Byte)))
	}

	bytes = bytes[offset : offset+length]
	//ptr := unsafe.Pointer(&bytes)

	f := bufio.NewWriter(file)
	defer f.Flush()
	nsize, err := f.Write(bytes)
	VM.ExecutionEngine.ioLogger.Info("🅹 �?%s - buffer size: %d, offset: %d, len: %d, actual write: %d \n", file.Name(), byteArr.ArrayLength(), offset, length, nsize)
	if err == nil {
		return
	}
	VM.Throw("java/lang/IOException", "Cannot write to file: %s", file.Name())
}

//----------------------------------------------------------------------------------------------
func JDK_java_io_UnixFileSystem_initIDs() {
	// do nothing
}

//@Native public static final int BA_EXISTS    = 0x01;
//@Native public static final int BA_REGULAR   = 0x02;
//@Native public static final int BA_DIRECTORY = 0x04;
//@Native public static final int BA_HIDDEN    = 0x08;
func JDK_java_io_UnixFileSystem_getBooleanAttributes0(this Reference, file Reference) Int {
	path := file.GetInstanceVariableByName("path", "Ljava/lang/String;").(JavaLangString).ToNativeString()
	if path == VM.contractPath {
		return 1
	}
	fileInfo, err := os.Stat(path)
	attr := 0
	if err == nil {
		attr |= 0x01
		if fileInfo.Mode().IsRegular() {
			attr |= 0x02
		}
		if fileInfo.Mode().IsDir() {
			attr |= 0x04
		}
		if hidden, err := IsHidden(path); hidden && err != nil {
			attr |= 0x08
		}
		return Int(attr)
	}

	VM.Throw("java/io/IOException", "Cannot get file attributes: %s", path)
	return -1

}

func IsHidden(filename string) (bool, error) {

	if runtime.GOOS != "windows" {

		// unix/linux file or directory that starts with . is hidden
		if filename[0:1] == "." {
			return true, nil

		} else {
			return false, nil
		}

	} else {
		//log.Fatal("Unable to check if file is hidden under this OS")
	}
	return false, nil
}

func JDK_java_io_UnixFileSystem_canonicalize0(this Reference, path JavaLangString) JavaLangString {
	str := filepath.Clean(path.ToNativeString())
	if runtime.GOOS == "windows" {
		if str[0] == '\\' || str[0] == '/' {
			str = str[1:]
		}
	}
	str = strings.Replace(str, "\\", "/", -1)
	return VM.NewJavaLangString(str)
}

func JDK_java_io_UnixFileSystem_getLength(this Reference, file Reference) Long {
	path := file.GetInstanceVariableByName("path", "Ljava/lang/String;").(JavaLangString).ToNativeString()
	if path == VM.contractPath {
		return Long(JDK_java_io_MemGetLength())
	}
	fileInfo, err := os.Stat(path)
	if err == nil {
		VM.ExecutionEngine.ioLogger.Info("📒    %s - length %d \n", path, fileInfo.Size())
		return Long(fileInfo.Size())
	}
	VM.Throw("java/io/IOException", "Cannot get file length: %s", path)
	return -1
}
