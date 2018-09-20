package cvm

import "math"

func register_java_lang_math() {
	VM.RegisterNative("java/lang/StrictMath.pow(DD)D", JDK_java_lang_StrictMath_pow)

	VM.RegisterNative("java/lang/Double.doubleToRawLongBits(D)J", JDK_jang_lang_Double_doubleToRawLongBits)
	VM.RegisterNative("java/lang/Double.longBitsToDouble(J)D", JDK_jang_lang_Double_longBitsToDouble)

	VM.RegisterNative("java/lang/Float.floatToRawIntBits(F)I", JDK_java_lang_Float_floatToRawIntBits)
	VM.RegisterNative("java/lang/Float.intBitsToFloat(I)F", JDK_java_lang_Float_intBitsToFloat)
	
}

// private static void registers()
func JDK_java_lang_StrictMath_pow(base Double, exponent Double) Double {
	return Double(math.Pow(float64(base), float64(exponent)))
}

// public static native int floatToRawIntBits(float value)
func JDK_jang_lang_Double_doubleToRawLongBits(value Double) Long {
	bits := math.Float64bits(float64(value))
	return Long(int64(bits))
}

// public static native int floatToRawIntBits(float value)
func JDK_jang_lang_Double_longBitsToDouble(bits Long) Double {
	value := math.Float64frombits(uint64(bits)) // todo
	return Double(value)
}

// public static native int floatToRawIntBits(float value)
func JDK_java_lang_Float_floatToRawIntBits(value Float) Int {
	bits := math.Float32bits(float32(value))
	return Int(int32(bits))
}

func JDK_java_lang_Float_intBitsToFloat(bits Int) Float {
	value := math.Float32frombits(uint32(bits))
	return Float(value)
}
