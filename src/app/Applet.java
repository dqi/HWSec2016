/**
 * 
 */
package app;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * @author Group 2!
 */

public class Applet extends javacard.framework.Applet implements ISO7816 {
	// Instrucions go here
	private static final byte INS_INIT_STUFF = (byte)0x02;
	private static final byte INS_WORK_WORK = (byte)0x12;

	private static final byte STATE_INIT = 0;
	private static final byte STATE_ISSUED = 1;

	/** The applet state (INIT or ISSUED). */
	byte state;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new app.Applet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
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
				 * 
				 * TODO
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