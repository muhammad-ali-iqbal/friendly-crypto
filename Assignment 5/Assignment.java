
package bitcoinj;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import java.security.Signature;

public class Assignment {
    
    public static void main(String args[])throws Exception{
		KeyPair keypair = generateRSAKkeyPair();
		String plainText = "Muhammad Ali Iqbal";
		byte[]cipherText = rsaEncryption(plainText,keypair.getPrivate());
		System.out.println("The Public Key is: "+ DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));
		System.out.println("The Private Key is: "+ DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));
		System.out.println("The Encrypted Text is: ");
		System.out.println(DatatypeConverter.printHexBinary(cipherText));
                
                
                
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keypair.getPrivate());
        String msg = "Muhammad Ali Iqbal";
        byte[] bytes = msg.getBytes();
        sign.update(bytes);
        byte[] signature = sign.sign();
       System.out.println("Digital signature: "+DatatypeConverter.printHexBinary(signature)); 
	}

	private static final String RSA = "RSA";
	public static KeyPair generateRSAKkeyPair()throws Exception{
		SecureRandom secureRandom1 = new SecureRandom();
		KeyPairGenerator kpg= KeyPairGenerator.getInstance(RSA);
		kpg.initialize(2048, secureRandom1);
		return kpg.generateKeyPair();
	}
	public static byte[] rsaEncryption(String plainText,PrivateKey privateKey)throws Exception{
		Cipher cypher= Cipher.getInstance(RSA);
		cypher.init(ENCRYPT_MODE, privateKey);
		return cypher.doFinal(plainText.getBytes());
                
	}
         
       
	
}

