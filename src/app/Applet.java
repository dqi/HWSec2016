/**
 * 
 */
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
	// Instrucions go here
	private static final byte INS_INIT_STUFF = (byte)0x02;
	private static final byte INS_WORK_WORK = (byte)0x12;

	private static final byte STATE_INIT = 0;
	private static final byte STATE_ISSUED = 1;

	/** Temporary buffer in RAM. */
	byte[] tmp;
	   
	/** The applet state (INIT or ISSUED). */
	byte state;
	
	/** Key for encryption. */
	RSAPublicKey pubKey;

	/** Key for decryption. */
	RSAPrivateKey privKey;

	/** Cipher for encryption and decryption. */
	Cipher cipher;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new app.Applet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	/** Constructor at applet-install-time; creates the key-structure and sets the state to STATE_INIT */
	public Applet() {
		tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
		pubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,false);
		privKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024,false);
		cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
		state = STATE_INIT;
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
				 * - Setting petrol balance to zero
				 * - (Register to car owner)
				 * - Setting the state to issued.
				 */
				switch(ins){
					case INS_INIT_STUFF:
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
						break;
					default:
						ISOException.throwIt(SW_INS_NOT_SUPPORTED);
				}
		}
	}
}