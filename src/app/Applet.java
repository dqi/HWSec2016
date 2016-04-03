package app;

import javacard.security.*;
import javacardx.crypto.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

/**
 * @author Group 2!
 */

public class Applet extends javacard.framework.Applet implements ISO7816 {
	// Instructions go here
	private static final byte INS_INIT_STUFF = (byte)0x02;
	private static final byte INS_ISSUE = (byte)0x10;
	private static final byte INS_PIN_SET = (byte)0x20;

	private static final byte INS_WORK_WORK = (byte)0x80;
	private static final byte INS_PIN_VERIFY = (byte)0x90;

	

	private static final byte STATE_INIT = 0;
	private static final byte STATE_ISSUED = 1;

	// Errors go here
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	// Variables go here
	/** Temporary buffer in RAM. */
	byte[] tmp;
	   
	/** The applet state (INIT or ISSUED). */
	byte state;
	
	/** Key for encryption. */
	RSAPublicKey pubKeyCard;

	/** Key for decryption. */
	RSAPrivateKey privKeyCard;
	
	/** Backend key for encryption */
	RSAPublicKey pubKeyBackEnd;

	/** Cipher for encryption and decryption. */
	Cipher cipher;
	
	/** Pincode */
	OwnerPIN pin;
	/** maximum number of incorrect tries before the PIN is blocked */
	final static byte PinTryLimit =(byte)0xff;
	/** maximum size PIN */
	final static byte MaxPinSize =(byte)0x04;
	
	/** Balance of the card, maximum of 32767 */
	short cardBalance;
	
	/** Personal ID */
	short id;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new app.Applet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	/** Constructor at applet-install-time; creates the key-structure and sets the state to STATE_INIT
	 * this is the only time we can create new data structures, so make it count.
	 */
	public Applet() {
		/** Transient array in RAM to use for 'things' (what?) */
		tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
		/** Card will establish a session key, store here */
		cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2,false);
		
		/** Things in EEPROM */
		/** When the applet is installed the state is STATE_INIT */
		state = STATE_INIT;
		/** Public key of the card, this should eventually be in a X509 structure. But I don't know how that works yet */
		pubKeyCard = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,false);
		/** Cards own private key */
		privKeyCard = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024,false);
		/** Public key of the back end, this should eventually be in a X509 structure. */
		pubKeyBackEnd = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,false);
		/** The revocation list */
		// TODO
		/** The pin structure */
		pin = new OwnerPIN(PinTryLimit, MaxPinSize);
		/** Initial balance is zero */
	    cardBalance = (byte)0x00;
	    /** Logging? */
	    // Log log = new log;
	}
	
	public void deselect() {
		/** If pin was validated this resets the validation and counter, else does nothing */
		pin.reset();
	}
	
	public boolean select() {
		/** Decline selection if blocked */
	  	if ( pin.getTriesRemaining() == 0 ) return false;
    	return true;
  	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		byte[] buf = apdu.getBuffer();
		byte ins = buf[OFFSET_INS];
		short lc = (short)(buf[OFFSET_LC] & 0x00FF);
		short outLength;

		if (selectingApplet()) {
			return;
		}
	  
		switch(state) {
			case STATE_INIT:
				/*
				 * The card is not yet initialized, there will need to be support for:
				 * - Uploading key material
				 * - Uploading card identification
				 * - Set pin code
				 * - (Register to car owner)
				 * - Setting the state to issued.
				 */
				switch(ins){
					case INS_INIT_STUFF:
						break;
					case INS_PIN_SET:
						// Receive pin and call pin.update()
						break;
					case INS_ISSUE:
						/* Issue the card, can not be undone */
						state = STATE_ISSUED;
						break;
					default:
						ISOException.throwIt(SW_INS_NOT_SUPPORTED);
				}
				break;
			case STATE_ISSUED:
				/* The card has been initialized, all the key material is assumed to be present.
				 * Support for:
				 * Charging terminal:
				 * - Validate card
				 * - PIN validation (Does this happen here? Find out what the OwnerPIN class can do to help with this)
				 * - View balance
				 * - Charge rations
				 * Petrol terminal:
				 * - View petrol allowance (different types?)
				 * - Decrease balance (to 0)
				 * - Increase (Write back)
				 * EOL
				 * - More relevant at infrastructure level, but maybe:
				 * Stolen:
				 * - If card number is reported as stolen the card will activate the alarm bells installed
				 * at every terminal and automatically call the police. 
				 */
				switch(ins) {
					case INS_WORK_WORK:
						if ( ! pin.isValidated()){
							ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
						// else work_work();
						}
						break;
					case INS_PIN_VERIFY:
						// pin_verify();
						break;
					default:
						ISOException.throwIt(SW_INS_NOT_SUPPORTED);
				}
		}
	}
}