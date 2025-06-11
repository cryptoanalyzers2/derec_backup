import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.CCMParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

import static java.lang.System.arraycopy;

public class AesCcm {

    BlockCipher engine = new AESEngine();
    CCMBlockCipher cipher=new CCMBlockCipher(engine);
    int macSize = 64;
    CCMParameters params;

    public void setKey(byte[] keybytes, byte[] nonce, byte[] AAD)
    {
        params = new CCMParameters(new KeyParameter(keybytes),
                macSize, nonce, AAD);
    }

    public byte[] encrypt(byte[] data) throws InvalidCipherTextException {
        cipher.init(true, params);
        byte[] outputText = new byte[cipher.getOutputSize(data.length)];
        byte[] ciphered = new byte[outputText.length+8];
        int outputLen = cipher.processBytes(data, 0, data.length,
                outputText , 0);
        cipher.doFinal(outputText, outputLen);
        byte[] tag= cipher.getMac();
        //we append it after the cipher
        arraycopy(outputText,(short)0,ciphered,(short)0,(short)outputText.length);
        arraycopy(tag,(short)0,ciphered,(short)outputText.length,(short)tag.length);
        return outputText;
    }

    public byte[] decrypt(byte[] ciphered, byte[] AAD) throws InvalidCipherTextException {
        cipher.init(false, params);
        byte[] outputText = new byte[cipher.getOutputSize(ciphered.length)];
        byte[] plaintext = new byte[outputText.length-8];
        byte[] tag = new byte[8];
        int outputLen = cipher.processBytes(ciphered, 0, ciphered.length,
                outputText , 0);
        cipher.doFinal(outputText, outputLen);
        arraycopy(outputText,0,plaintext,0,outputText.length-8);
        arraycopy(outputText,outputText.length-8,tag,0,8);
        //we check the tag
        //?? how we do that

        return outputText;
    }

    public boolean autotest() throws IllegalStateException, InvalidCipherTextException {

        try {
            byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            byte[] iv = "12345678".getBytes();
            byte[] AAD = "LESECRET".getBytes();

            //16 bytes payload
            String input = "AABBCCDDAABBCCDDAABBCCDDAABBCCDD";
            byte[] inputData = Hex.decode(input);

            this.setKey(key, iv, AAD);

            byte[] encrypted = this.encrypt(inputData);
            byte[] decrypted = this.decrypt(encrypted, AAD);
            int res = Arrays.compare(inputData,decrypted);

            if(res==0)
            {
                return true;
            }

        }
        catch(Exception ex)
        {
            ex.printStackTrace();
        }

        return false;



    }
}
