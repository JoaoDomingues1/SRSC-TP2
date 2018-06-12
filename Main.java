import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import redis.clients.jedis.Jedis;

public class Main {

	private static final int TOTAL_OPERATIONS = 100;

	private static final String cipherSuite = "AES/CBC/PKCS5Padding";
	private static final int keySize = 256;

	private static final String MAC = "DES";
	private static final int macKeySize = 64;

	private static final String hashFunction = "SHA1";

	private static final int nFirstBits = 24;

	private static final int nColumns = 6;

	static byte[] ivBytes = new byte[] {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 
	};

	private static LinkedList<HashMap<ByteArray, LinkedList<ByteArray>>> index = new LinkedList<HashMap<ByteArray, LinkedList<ByteArray>>>();
	private static HashMap<ByteArray, Integer> signatureSizesByKey = new HashMap<ByteArray, Integer>();

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IntegrityCheckFailedException, ShortBufferException, SignatureException, AuthenticityCheckFailedException {

		for(int i = 0; i < nColumns; i++)
			index.add(new HashMap<ByteArray, LinkedList<ByteArray>>());

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance(cipherSuite, "BC");
		byte[] password = buildRandomPassword(keySize);

		byte[] macPassword = buildRandomPassword(macKeySize);
		Mac mac = Mac.getInstance(MAC, "BC"); // integrity MAC
		Key macKey = new SecretKeySpec(macPassword, mac.getAlgorithm());

		MessageDigest hash = MessageDigest.getInstance(hashFunction, "BC");

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
		kpg.initialize(ecSpec, new SecureRandom());
		KeyPair keyPair = kpg.generateKeyPair();
		Signature signature = Signature.getInstance("SHA512withECDSA", "BC");

		Jedis jedis = new Jedis("192.168.55.3", 6379);

		jedis.connect();
		jedis.flushAll();

		String[][] table = buildTable();
		byte[][][] result = encryptCreateKeyAndAddIndexes(table, hash, cipher, password, ivSpec, mac, macKey, signature, keyPair);

		long begin = Calendar.getInstance().getTimeInMillis();

		for(int i = 0; i < TOTAL_OPERATIONS;i++)
		{
			jedis.set(result[i][0], result[i][1]);
		}


		//		LinkedList<String> temp = getEntrysByColumn(2, "DataEmissao34", hash, jedis, cipher, password, ivSpec, mac, macKey, signature, keyPair.getPublic());
		//		Iterator<String> it = temp.iterator();
		//		while(it.hasNext())
		//			System.out.println(it.next());

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(password, cipher.getAlgorithm()), ivSpec);
		mac.init(macKey);
		signature.initVerify(keyPair.getPublic());
		for(int i = 0; i < TOTAL_OPERATIONS;i++)
		{
			byte[] authenticatedPayload = checkAuthenticityAndGetPayload(jedis.get(result[i][0]), signature, signatureSizesByKey.get(new ByteArray(result[i][0])));

			byte[] decripted = cipher.doFinal(authenticatedPayload);
			System.out.println(new String(checkIntegrityAndGetPayload(decripted, mac)));
		}
		
		HashSet<ByteArray> set = new HashSet<ByteArray>();
		Iterator<HashMap<ByteArray, LinkedList<ByteArray>>> it = index.iterator();
		while(it.hasNext())
		{
			HashMap<ByteArray, LinkedList<ByteArray>> map= it.next();
			Iterator<LinkedList<ByteArray>> it2 = map.values().iterator();
			while(it2.hasNext())
			{
				LinkedList<ByteArray> list = it2.next();
				Iterator<ByteArray> it3 = list.iterator();
				while(it3.hasNext())
				{
					set.add(it3.next());
				}
			}
		}
		Iterator<ByteArray> it4 = set.iterator();
		while(it4.hasNext())
		{
			jedis.del(it4.next().byteArray);
		}
		
		long elapsed = Calendar.getInstance().getTimeInMillis() - begin;

		jedis.disconnect();

		System.out.println(((1000 * 3 * TOTAL_OPERATIONS) / elapsed) + " ops/s");

	}

	private static String[][] buildTable()
	{
		String[][] table = new String[TOTAL_OPERATIONS][nColumns];

		for(int i = 0; i < TOTAL_OPERATIONS; i++)
		{
			table[i][0] = "NumeroCliente"+i;//numero cliente
			table[i][1] = "CartaoCidadao"+i;//cartao cidadao
			table[i][2] = "DataEmissao"+i;//data emissao
			table[i][3] = "Morada"+i;//morada
			table[i][4] = "NumeroTelefone"+i;//telefone
			table[i][5] = "NumeroContribuinte"+i;//numero contribuinte
		}
		return table;
	}

	private static byte[][][] encryptCreateKeyAndAddIndexes(String[][] table, MessageDigest hash, Cipher cipher, byte[] password, IvParameterSpec ivSpec, Mac mac, Key macKey, Signature signature, KeyPair keyPair) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, SignatureException
	{
		byte[][][] result = new byte[100][2][];

		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(password, cipher.getAlgorithm()), ivSpec);

		mac.init(macKey);

		for(int i = 0; i < TOTAL_OPERATIONS; i++)
		{
			String entry = table[i][0] + ":" + table[i][1] + ":" + table[i][2] + ":" + table[i][3] + ":" + table[i][4] + ":" + table[i][5];

			byte[][] hashs = new byte[nColumns][];
			for(int a = 0; a < nColumns; a++)
				hashs[a] = hash.digest(table[i][a].getBytes());
			//primeiros 24 byt ou 3 bytes
			int nFirstBytes = nFirstBits/3;
			byte[] tempKey = new byte[nFirstBytes*nColumns];
			for(int q = 0; q < nColumns; q++)
				for(int a = 0; a < nFirstBytes; a++)
					tempKey[q*nFirstBytes + a] = hashs[q][a];

			byte[] entryBytes = entry.getBytes();

			ByteArray key = new ByteArray(tempKey);

			for(int a = 0; a < nColumns; a++)
				addIndex(index.get(a), hashs[a], key);	

			byte[] macResult = mac.doFinal(entryBytes);

			byte[] encryptedText = new byte[cipher.getOutputSize(mac.getMacLength() + entryBytes.length)];
			int last_offset = cipher.update(entryBytes, 0, entryBytes.length, encryptedText, 0);
			cipher.doFinal(macResult, 0, macResult.length, encryptedText, last_offset);

			//			cipher.update(entryBytes);
			//			byte[] encryptedText = cipher.doFinal(macResult);

			signature.initSign(keyPair.getPrivate(), new SecureRandom());
			signature.update(encryptedText);
			byte[] sigBytes = signature.sign();

			signatureSizesByKey.put(key, sigBytes.length);

			byte[] encryptedTextPlusSign = new byte[encryptedText.length+sigBytes.length];
			for(int a = 0; a < encryptedText.length; a++)
				encryptedTextPlusSign[a] = encryptedText[a];
			for(int a = 0; a < sigBytes.length; a++)
				encryptedTextPlusSign[encryptedText.length+a] = sigBytes[a];

			result[i][0] = key.byteArray;
			result[i][1] = encryptedTextPlusSign;
		}
		return result;
	}

	private static void addIndex(HashMap<ByteArray, LinkedList<ByteArray>> index, byte[] key, ByteArray value)
	{
		ByteArray newKey = new ByteArray(key);
		if(!index.containsKey(newKey))
			index.put(newKey, new LinkedList<ByteArray>());
		index.get(newKey).add(value);
	}

	private static byte[] buildRandomPassword(int size)
	{
		byte[] password = new byte[size/8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(password);
		return password;
	}

	private static LinkedList<String> getEntrysByColumn(int indexIndex, String text, MessageDigest hash, Jedis jedis, Cipher cipher, byte[] password, IvParameterSpec ivSpec, Mac mac, Key macKey, Signature signature, PublicKey publicKey) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IntegrityCheckFailedException, SignatureException, AuthenticityCheckFailedException
	{
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(password, cipher.getAlgorithm()), ivSpec);

		mac.init(macKey);

		signature.initVerify(publicKey);

		ByteArray hashedText = new ByteArray(hash.digest(text.getBytes()));

		Iterator<ByteArray> it = index.get(indexIndex).get(hashedText).iterator();
		LinkedList<String> result = new LinkedList<String>();
		while(it.hasNext())
		{
			ByteArray current = it.next();

			byte[] authenticatedPayload = checkAuthenticityAndGetPayload(jedis.get(current.byteArray), signature, signatureSizesByKey.get(current));

			byte[] decrypted = cipher.doFinal(authenticatedPayload);

			String tempResult = new String(checkIntegrityAndGetPayload(decrypted, mac));
			String[] stringArray = tempResult.split(":");
			if(stringArray[indexIndex].equals(text))
				result.add(new String(checkIntegrityAndGetPayload(decrypted, mac)));
		}
		return result;
	}

	private static byte[] checkAuthenticityAndGetPayload(byte[] input, Signature signature, int signatureSize) throws SignatureException, AuthenticityCheckFailedException
	{
		int length = input.length - signatureSize;
		signature.update(input, 0, length);
		ensureAuthenticity(signature.verify(input, length, signatureSize), "Invalid signature");

		byte[] payload = new byte[length];
		for(int i = 0; i < length; i++)
			payload[i] = input[i];

		return payload;
	}

	private static byte[] checkIntegrityAndGetPayload(byte[] input, Mac mac) throws IntegrityCheckFailedException
	{
		int length = input.length - mac.getMacLength();
		mac.update(input, 0, length);
		byte[] macResult = mac.doFinal();
		for(int i = 0; i < macResult.length; ++i)
			ensureIntegrity(macResult[i] == input[length + i], "Invalid integrity MAC");

		byte[] entryBytes = new byte[length];
		for(int i = 0; i < length; i++)
			entryBytes[i] = input[i];

		return entryBytes;
	}

	static private void ensureIntegrity(boolean expr, String msg) throws IntegrityCheckFailedException {
		if(!expr)
			throw new IntegrityCheckFailedException(msg);
	}

	private static void ensureAuthenticity(boolean expr, String msg) throws AuthenticityCheckFailedException {
		if(!expr)
			throw new AuthenticityCheckFailedException(msg);
	}
}
