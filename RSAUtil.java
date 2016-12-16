

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.Test;

public class RSAUtil {
	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	public static final String PUBLIC_KEY = "RSAPublicKey";
	public static final String PRIVATE_KEY = "RSAPrivateKey";

	private static String privateKey = "";
	private static String publicKey = "";

	static {
		privateKey = readPrivateKey();
		publicKey = readPublicKey();
	}

	/**
	 * 从文件读取私钥,暂时写定值.
	 * 
	 * @return
	 */
	private static String readPrivateKey() {
		String defaultKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIooiQrO6C/0BRsYVYAPITJmSA/EQuJH5C/LlHP4jl+sUBZBVzrAgu7O+60cllkhoa0HR9tGOiggjabFPbjCduYQjkhAAvdTMTuQUIERuy0mxl/eZNviQjFmK/1T/rPMWg3uzOh0Q0Y2hdbp1isSYhbL3tBAB8vFOzhNa3lclOovAgMBAAECgYAmyw7/6+0iWeB9JS4M0TK/Fh0x4CfvpcQa74z1q1s+3gF23k4B/0BEkfX1O8uzp0/gZ+TzWxrFXa6on0WfdWsw74A9ev0iWs7Zy64plR47/vtAvudai4iFSG0Q05bfyPjBSzJNrkhsjgOjy/ZoXkjEcF/VumeWq+s2q3x1KvnmMQJBAN0jvubNNSKQWuwyy6hwUK/SN6YXG64pkl7erYJpu3KcBmh7F4n2i2sNfjH8jxiHqbaoSg5DnypF6AlJKol1bxsCQQCf8ASWaYTB51hM+YyFetAJ5dT/vPB985rs5J++xxaRjEAP06dzYetP57mTZiOTctSuGM7IDFURH9jIwDj2sZ59AkAW5daki2cPFydzAad433hbXEcK2aWyGPfg/um0cUJJkcJQGz7KuE6jXRhOELq4bYOzOCXC6FmYxPhLzdmrtg81AkAqszD2W1uXTUWU33c119EdI2BXmsD2T4iIQI2pqIuM9k3QK+jj9DuXzL0N7lIHNrwzcuoaHLjFZqRBDJjovAkdAkBaH83CP5A9eUCXBn1mdHrwrZXnaL6iSqq9smAINmLgrdci6h2JettA/le6b/T9OTLONd9sXnvQiC+eoY+dIqdl";
		return defaultKey;
	}

	/**
	 * 从文件读取公钥,暂时写定值.
	 * 
	 * @return
	 */
	private static String readPublicKey() {
		String defaultKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKKIkKzugv9AUbGFWADyEyZkgPxELiR+Qvy5Rz+I5frFAWQVc6wILuzvutHJZZIaGtB0fbRjooII2mxT24wnbmEI5IQAL3UzE7kFCBEbstJsZf3mTb4kIxZiv9U/6zzFoN7szodENGNoXW6dYrEmIWy97QQAfLxTs4TWt5XJTqLwIDAQAB";
		return defaultKey;
	}

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            私钥
	 * 
	 * @return
	 * @throws Exception
	 */

	public static String sign(byte[] data, String privateKey) throws Exception {
		// 解密由base64编码的私钥

		byte[] keyBytes = decryptBASE64(privateKey);// decryptBASE64(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);

		return encryptBASE64(signature.sign());
	}

	/**
	 * 校验数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Base64DecodingException
	 * @throws Exception
	 * 
	 */

	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

		// 解密由base64编码的公钥
		byte[] keyBytes = decryptBASE64(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
		// 对公钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 加密<br>
	 * 用私钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * 取得私钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return encryptBASE64(key.getEncoded());
	}

	/**
	 * 取得公钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);

		return encryptBASE64(key.getEncoded());
	}

	/**
	 * 初始化密钥
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);

		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		Map<String, Object> keyMap = new HashMap<String, Object>(2);

		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	public static String decrypt(String inputData) throws Exception {
		String privateKey = RSAUtil.privateKey;
		byte[] decrypt = RSAUtil.decryptByPrivateKey(decryptBASE64(inputData), privateKey);
		return new String(decrypt, "UTF-8");
	}

	public static String encrypt(String inputData) throws Exception {
		byte[] data = inputData.getBytes("UTF-8");
		String publicKey = RSAUtil.publicKey;
		byte[] encrypt = RSAUtil.encryptByPublicKey(data, publicKey);
		return encryptBASE64(encrypt);
	}

	private static String encryptBASE64(byte[] b) {
		return Base64.encodeBase64String(b);
	}

	private static byte[] decryptBASE64(String v) {
		return Base64.decodeBase64(v);
	}
	
	//@Test
	public void test() throws Exception {
		String decryptStr = decrypt("ezwdtHVpPni");
		System.out.println(decryptStr);
	}

	public static String getPrivateKey() {
		return privateKey;
	}

	public static String getPublicKey() {
		return publicKey;
	}

}
