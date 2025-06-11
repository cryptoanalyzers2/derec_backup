import javax.crypto.Cipher;
import javax.smartcardio.*;
//import java.security.MessageDigest;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.random.RandomGenerator;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.CCMParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import static java.lang.System.arraycopy;

public class test_secureChannel {


    static AesCcm aes= new AesCcm();


    static byte[] my_random;
    static byte[] their_random;

    static byte[] our_secret;
    static byte[] the_key_bytes;

    static RandomGenerator m_rngRandom;

    static MessageDigest sha256;

    static byte[] tmp;

    static boolean autotest=false;


    static byte[] our_nonce;
    static byte[] my_tag;
    static byte[] my_message;
    static byte[] their_tag;

    static byte[] their_message;
    static byte[] their_message_ciphered;

    static byte[] my_message_ciphered;

    byte counter=0;

    static CardChannel channel;
    static byte INS_GEN_RND= 0x0B;
    static byte INS_AUTOTEST = 0x0A;
    static byte INS_SEND_RECEIVE_ENCRYPTED = 0x0C;

    static byte[] applet_AID = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x00};


   public static void init() throws NoSuchAlgorithmException {

        my_random= new byte[8];
        their_random= new byte[8];
        //our_secret || their_random || my_random
        the_key_bytes = new byte[8+8+8];
        //LESECRET in ASCIII
        our_secret = new byte[]{(byte)0x4c ,(byte)0x45 ,(byte)0x53 ,(byte)0x45 ,(byte)0x43 ,(byte)0x52 ,(byte)0x45 ,(byte)0x54};
        m_rngRandom = RandomGenerator.getDefault();
        sha256= MessageDigest.getInstance("SHA-256");
        tmp= new byte[128];
        my_tag= new byte[8];
        my_message= new byte[16];
        their_tag= new byte[8];
        our_nonce= new byte[8];
        their_message = new byte[16];
        their_message_ciphered = new byte[24];
        my_message_ciphered = new byte[24];
    }

    public static String generateRandomWord(int letters)
    {

        Random random = new Random();

        char[] word = new char[letters]; // words of length 3 through 10. (1 and 2 letter words are boring.)
        for(int j = 0; j < word.length; j++)
        {
            word[j] = (char)('a' + random.nextInt(26));
        }
        return new String(word);

    }

    static private void receiveAndSendEncryptedMessage() {

       try {
           //generate some message
           my_message = generateRandomWord(16).getBytes();
           System.out.println("message generated sent to card");
           printHex(my_message);

           //DEBUG
           //my_message= new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};


           my_message_ciphered = Encrypt(my_message);
           CommandAPDU apdu = new CommandAPDU(0x00,INS_SEND_RECEIVE_ENCRYPTED,0x00,0x00,my_message_ciphered);
           ResponseAPDU apdu2;
           printHex(apdu.getBytes());
           apdu2 = channel.transmit(apdu);
           System.out.println(String.format("0x%04X", apdu2.getSW()));

           if(apdu2.getSW()!=0x9000)
           {
               throw new Exception("error sending encrypted message to card");
           }

           System.out.println("received encrypted answer from card");

            arraycopy(apdu2.getBytes(),0,their_message_ciphered,0,their_message_ciphered.length);

            printHex(apdu2.getBytes());

           their_message=Decrypt(their_message_ciphered);
           System.out.println("deciphered answer from card");

           printHex(their_message);

       }
       catch(Exception ex)
       {
            ex.printStackTrace();
       }

    }

    static  private byte[] Decrypt(byte[] data) throws InvalidCipherTextException {

        return aes.decrypt(data,our_secret);

    }

    static   private byte[] Encrypt(byte[] data) throws InvalidCipherTextException {

        return aes.encrypt(data);

    }

    static void printHex(byte[] bytes)
    {
        for (byte b : bytes) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.print("\n");
    }


    static void selectApplet() throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00,0xA4,0x04,0x00,applet_AID);
        printHex(apdu.getBytes());
        //send random and get card's random
        ResponseAPDU apdu2=channel.transmit(apdu);
        System.out.println(String.format("0x%04X", apdu2.getSW()));

        if(apdu2.getSW()!=0x9000)
        {
            throw new Exception("Applet not selected");
        }

        System.out.println("Applet selected");

    }

    static  private void generateNonce()
    {
        for(short u=0;u<8;u++)
        {
            our_nonce[u]=(byte)(my_random[u] ^ their_random[u]);
        }
    }


    static   private void receiveAndSendRandom() throws Exception {

         //generate our random number

        m_rngRandom.nextBytes(my_random);

        CommandAPDU apdu = new CommandAPDU(0x00,INS_GEN_RND,0x00,0x00,my_random);
        printHex(apdu.getBytes());
        //send random and get card's random
        ResponseAPDU apdu2=channel.transmit(apdu);
        System.out.println(String.format("0x%04X", apdu2.getSW()));

        if(apdu2.getSW()!=0x9000)
        {
            throw new Exception("error sending random to card");
        }


        System.out.println("random received from card");
        printHex(apdu2.getBytes());

        //store their random number
        arraycopy(apdu2.getBytes(),(short)0,their_random,(short)0,(short)8);

        generateNonce();
        System.out.println("Nonce generated:");
        printHex(our_nonce);
        generateKey();
        System.out.println("key generated");

    }

    static  void generateKey() throws DigestException {

        //our_secret || their_random || my_random
        arraycopy(our_secret,(short)0, the_key_bytes, (short)0, (short)8);
        arraycopy(my_random,(short)0, the_key_bytes, (short)8, (short)8);
        arraycopy(their_random,(short)0, the_key_bytes, (short)16, (short)8);
        sha256.update(the_key_bytes,0,24);
        tmp=sha256.digest();

        ////DEBUG
        //tmp=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        //our_nonce=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        //our_secret=new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        printHex(tmp);

        //set key using tmp
        aes.setKey(tmp,our_nonce,our_secret);
        Arrays.fill(tmp, (short)0, (short)32, (byte)0);
    }






public static void main(String[] params)  {
    try {
        init();

        boolean res= aes.autotest();

        if(res==false)
        {
            System.out.println("autotest failed");
            System.exit(-1);
        }
        System.out.println("autotest succeeded");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("List of card readers: " + terminals);

        //we get the first reader
        CardTerminal terminal = terminals.get(0);

        System.out.println("Card reader: " + terminal);
        //we obtain the card
        Card card = terminal.connect("*");

        channel = card.getBasicChannel();

        selectApplet();

        receiveAndSendRandom();

        receiveAndSendEncryptedMessage();

    }
    catch(Exception ex)
    {
        ex.printStackTrace();
    }


}


}
