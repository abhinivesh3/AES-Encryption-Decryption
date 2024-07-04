import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AES {
    private SecretKey secretKey;
    private int KEY_SIZE = 128; // possible KEY_SIZE values are 128, 192 and 256
    private int T_LEN = 128; // possible T_LEN values are 128, 120, 112, 104 and 96
    private Cipher encryptionCipher;

    public void init(){
        try{
            KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE);
            secretKey=keyGenerator.generateKey();
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("Error while KeyGenerator : "+e);
        }
    }

    public String encrypt(String message){
        try{
            byte[] messageInBytes = message.getBytes();
            encryptionCipher=Cipher.getInstance("AES/GCM/NoPadding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptionBytes = encryptionCipher.doFinal(messageInBytes);
            return encode(encryptionBytes);
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(NoSuchPaddingException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(InvalidKeyException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(IllegalBlockSizeException e){
           System.out.println("Error while encrypt : "+e);
        }
        catch(BadPaddingException e){
            System.out.println("Error while encrypt : "+e);
        }
        return null;
    }

    public String decrypt(String encryptedMessage){
        try{
            byte[] messageInBytes = decode(encryptedMessage);
            Cipher decryptionCiphere = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec=new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
            decryptionCiphere.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            byte[] decryptionByte = decryptionCiphere.doFinal(messageInBytes);
            return new String(decryptionByte);
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(NoSuchPaddingException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(InvalidAlgorithmParameterException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(InvalidKeyException e){
            System.out.println("Error while encrypt : "+e);
        }
        catch(IllegalBlockSizeException e){
           System.out.println("Error while encrypt : "+e);
        }
        catch(BadPaddingException e){
            System.out.println("Error while encrypt : "+e);
        }
        return null;
    }
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode (String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args){
        AES aes=new AES();
        aes.init();
        String encryptedMessage= aes.encrypt("Hello, World");
        String decryptedMessage = aes.decrypt(encryptedMessage);

        System.out.println(encryptedMessage);
        System.out.println(decryptedMessage);

    }
}