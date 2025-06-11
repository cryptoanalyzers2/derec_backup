package deRec;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.*;

public class deRec extends Applet {

	Cipher aesgcm;
	AEADCipher aead;
	
	byte[] my_random;
	byte[] their_random;
	
	byte[] our_secret;
	byte[] the_key_bytes;
	
	RandomData m_rngRandom;
	
	MessageDigest sha256;
	
	byte[] tmp;
	
	boolean autotest=false;
	AESKey aeskey ;
	
	byte[] our_nonce;
	byte[] my_tag;
	byte[] my_message;
	byte[] their_tag;
	
	byte[] their_message;
	
	byte counter=0;
	
	public deRec()
	{
		aead = (AEADCipher)Cipher.getInstance(AEADCipher.ALG_AES_CCM,false);
		my_random= new byte[8];
		their_random= new byte[8];
		//our_secret || their_random || my_random
		the_key_bytes = new byte[8+8+8];
		//LESECRET in ASCIII
		our_secret = new byte[]{(byte)0x4c ,(byte)0x45 ,(byte)0x53 ,(byte)0x45 ,(byte)0x43 ,(byte)0x52 ,(byte)0x45 ,(byte)0x54};
		m_rngRandom = RandomData.getInstance(RandomData.ALG_TRNG);
		sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		tmp= new byte[128];
		my_tag= new byte[8];
		my_message= new byte[16];
		their_tag= new byte[8];
		our_nonce= new byte[8];
		their_message = new byte[16];
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new deRec().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	/*
	 * autotest pour AES-CCM
	 */
	void encryptAutoTest()
	{
		if(autotest=true)
		{
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
		
		try
		{
		byte[] keybytes=new byte[32];
		keybytes[1]=0x01;
		
		AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128, false);
	
		key.setKey(keybytes,(short)0);
		byte[] nonce= new byte[8];
		nonce[0]=0x02;
		
		/*
		 * theKey - the key object to use for encrypting or decrypting
theMode - one of MODE_DECRYPT or MODE_ENCRYPT
adataLen - the length of the authenticated data as presented in the updateAAD method
nonceBuf - a buffer holding the nonce
nonceOff - the offset in the buffer of the nonce
nonceLen - the length in the buffer of the nonce
messageLen - the length of the message as presented in the update and doFinal methods
tagSize - the size in in bytes of the authentication tag

		 */
		
		/*
		 * public abstract void init(Key theKey,
        byte theMode,
        byte[] nonceBuf,
        short nonceOff,
        short nonceLen,
        short adataLen,
        short messageLen,
        short tagSize)
		 */
		
		byte[] message = {0x01, 0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01, 0x02,0x03,0x04,0x05,0x06,0x07,0x08};
		byte[] output = new byte[64];
		byte[] output2 = new byte[64];
		byte[] tag = new byte[8];
		byte[] tag2 = new byte[8];
		
		aead.init((Key)key, AEADCipher.MODE_ENCRYPT,nonce,(short)0x00,(short)0x08,(short)0x08,(short)16,(short)0x08);
		aead.updateAAD(new byte[] {0x01, 0x02,0x03,0x04,0x05,0x06,0x07,0x08}, (short)0x00,(short)0x08);
		//short len_enc2 =aead.update(message, (short)16,(short) 0, output, (short)0x00);
		
		short len_enc =aead.doFinal(message,(short) 0, (short)16, output, (short)0x00);
		//decryption test
		
		aead.retrieveTag(tag, (short)0, (short)8);
		
		aead.init((Key)key, AEADCipher.MODE_DECRYPT,nonce,(short)0x00,(short)0x08,(short)0x08,(short)16,(short)0x08);
		aead.updateAAD(new byte[] {0x01, 0x02,0x03,0x04,0x05,0x06,0x07,0x08}, (short)0x00,(short)0x08);
		
		aead.doFinal(output, (short) 0, (short)16, output2, (short)0x00);
		
		
		
		//check#1
		//byte res=Util.arrayCompare(tag, (short) 0, tag2, (short) 0, (short) 16);
		
		boolean res=aead.verifyTag(tag, (short)0, (short)8, (short)8);
		
		if(res!=true)
		{
			ISOException.throwIt((short)0x7808);
		}
		
		//check#2
		
		byte res2=Util.arrayCompare(message, (short) 0, output2, (short) 0, (short) 16);
		
		if(res2!=0)
		{
			ISOException.throwIt((short)0x7809);
		}
				
		autotest=true;
		ISOException.throwIt(ISO7816.SW_NO_ERROR);
		
		}
		catch(CryptoException ex)
		{
			ISOException.throwIt((short)(0x7000+ex.getReason()));
		}
		
	}
	
	void generateKey()
	{
		
		//our_secret || their_random || my_random
		Util.arrayCopy(our_secret,(short)0, the_key_bytes, (short)0, (short)8);
		Util.arrayCopy(their_random,(short)0, the_key_bytes, (short)8, (short)8);
		Util.arrayCopy(my_random,(short)0, the_key_bytes, (short)16, (short)8);
		
		sha256.doFinal(the_key_bytes,(short)0, (short)24, tmp, (short)0);
		
		//debug
		//tmp=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        //our_nonce=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        //our_secret=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        
		aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_256, false);
		aeskey.setKey(tmp, (short)0);
		//zeroization
		Util.arrayFillNonAtomic(tmp, (short)0, (short)32, (byte)0);
	}
	
	/*
	 * encrypt data with CCM
	 */
	void Encrypt(APDU apdu)
	{
		try
		{
		byte[] buf = apdu.getBuffer();
		aead.init((Key)aeskey, AEADCipher.MODE_ENCRYPT,our_nonce,(short)0x00,(short)0x08,(short)0x08,(short)16,(short)0x08);
		aead.updateAAD(our_secret,(short)0x00,(short)0x08);
		//short len_enc2 =aead.update(message, (short)16,(short) 0, output, (short)0x00);
		
		short len_enc =aead.doFinal(my_message,(short) 0, (short)16, buf, (short)0x00);
		//decryption test
		
		aead.retrieveTag(my_tag, (short)0, (short)8);
		
		Util.arrayCopy(my_tag, (short)0, buf, (short)16, (short)8);
		
		apdu.setOutgoingAndSend((short)0x00, (short)24);
		}
		catch(CryptoException ex)
		{
			ISOException.throwIt((short)(0x5700+ex.getReason()));
		}
		catch(ArrayIndexOutOfBoundsException ex)
		{
			ISOException.throwIt((short)0x5756);
		}
		catch(NullPointerException ex)
		{
			ISOException.throwIt((short)0x7757);
		}
		
	}
	
	/*
	 * decrypt data with CCM
	 */
	void Decrypt(APDU apdu)
	{
		try
		{
		byte[] buf = apdu.getBuffer();
		aead.init((Key)aeskey, AEADCipher.MODE_DECRYPT,our_nonce,(short)0x00,(short)0x08,(short)0x08,(short)16,(short)0x08);
		
		//Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, their_message, (short)0,(short)16);
		Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA+16), their_tag, (short)0,(short)8);
		
		aead.updateAAD(our_secret, (short)0x00,(short)0x08);
		
		aead.doFinal(buf, ISO7816.OFFSET_CDATA, (short)16, their_message, (short)0x00);
		
		boolean res=aead.verifyTag(their_tag, (short)0, (short)8, (short)8);
		
		if(res!=true)
		{
			ISOException.throwIt((short)0x7755);
		}
		}
		catch(CryptoException ex)
		{
			ISOException.throwIt((short)(0x7700+ex.getReason()));
		}
		catch(ArrayIndexOutOfBoundsException ex)
		{
			ISOException.throwIt((short)0x7756);
		}
		catch(NullPointerException ex)
		{
			ISOException.throwIt((short)0x7757);
		}
		
	}
	

	
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x0A:
			encryptAutoTest();
			break;
		case (byte) 0x0B:
			receiveAndSendRandom(apdu);
			break;
		case (byte) 0x0C:
			receiveAndSendEncryptedMessage(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void receiveAndSendEncryptedMessage(APDU apdu) {
		
		if(counter<0xFF)
		{
			counter++;
		}
		else
		{
			counter=0;
		}
		
		
		
		Decrypt(apdu);
		Util.arrayCopy(their_message, (short)0, my_message, (short)0, (short)16);
		my_message[0]=counter;
		
		 //DEBUG
        //my_message= new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

        
		Encrypt(apdu);
		
	}
	
	private void generateNonce()
	{ 
		   for(short u=0;u<8;u++)
		   {
			   our_nonce[u]=(byte)(my_random[u] ^ their_random[u]);
		   }
	}
	

	private void receiveAndSendRandom(APDU apdu) {
		
		byte[] buf=apdu.getBuffer();
		//store their random number
		Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, their_random, (short)0, (short)8);
		//generate our random number
		 
	    m_rngRandom.nextBytes(my_random, (short)0, (short)8);
	 
	    generateNonce();
	    generateKey();
	    
	    Util.arrayCopy(my_random, (short)0, buf, (short)0, (short)8);
	    apdu.setOutgoingAndSend((short)0, (short)8);
		
	}

}
