package cvm

/*
Type system:

<Type>
  |- PrimitiveType
        |- *ByteType
        |- *ShortType
        |- *CharType
        |- *IntType
        |- *LongType
        |- *FloatType
        |- *DoubleType
        |- *BooleanType
  |- *ReturnAddressType
  |- *Class
*/

type Type interface {
	Name() string
	Descriptor() string
	ClassObject() Reference
}

//---------------------------------------------------------------------------------------
/*
Value system:

<Value>
	|- Byte     -> int8
	|- Short    -> int16
	|- Char     -> uint16
	|- Int      -> int32
	|- Long     -> int64
	|- Float    -> float32
	|- Double   -> float64
	|- Boolean  -> int8
	|- Reference ( -> *Object)
		|= : ObjectRef
		|= : ArrayRef
	    |= : JavaLangString
	    |= : JavaLangThread
	    |= : JavaLangClass
	    |= : JavaLangClassLoader
	    |= : ...

ObjectRef and ArrayRef are only reference value holding a pointer to real heap object <Object> or <Array>.
The reference itself will be never nil, but its containing pointer can be nil, which means the reference is `NULL` in Java.
In Java, all the values are passed by copying, so never use pointers of these values including Reference.
*/
type Value interface {
	Type() Type
}
