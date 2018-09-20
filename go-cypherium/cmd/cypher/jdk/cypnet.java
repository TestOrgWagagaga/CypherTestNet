package javax.cypher;

public final class cypnet
{
  public static native boolean SetTokenInfo(String symbol, String name, long totalSupply, String _owner );
  
  public static native String  GetAddress(String addressType); //can be "caller","self","owner" and other filter
  
  public static native long   BalanceOf(String _address );
  public static native boolean ChangeBalance(String _from, long _value);

  public static native boolean Transfer(String _from, String _to, long _value);

  public static native boolean SetState(String _key, String _value );
  public static native String GetState(String _key);

  static {}
}
