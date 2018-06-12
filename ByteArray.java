
public class ByteArray {

	public byte[] byteArray;
	
	public ByteArray(byte[] byteArray)
	{
		this.byteArray = byteArray;
	}
	
//	public boolean equals(ByteArray byteArray)
	public boolean equals(Object a)
	{
		ByteArray byteArray = (ByteArray) a;
		byte[] newByteArray = byteArray.byteArray;
		if(this.byteArray.length!=newByteArray.length)
			return false;
		for(int i = 0; i < newByteArray.length;i++)
			if(this.byteArray[i]!=newByteArray[i])
				return false;
		return true;
	}
	

	public int hashCode()
	{
		int result = 0;
		for(int i = 0; i < byteArray.length;i++)
		{
			result += byteArray[i];
		}
		return result;
	}
}
