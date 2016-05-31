package app;

import javacard.security.*;
import javacardx.crypto.*;

import javacard.framework.*;

/**
 * 
 * @author Group 2!
 * 
 *         APDU Structure cheat sheet: CLA (1 byte): Class of instruction ---
 *         indicates the structure and format for a category of command and
 *         response APDUs INS (1 byte): Instruction code: specifies the
 *         instruction of the command P1 (1 byte) and P2 (1 byte): Instruction
 *         parameters -- further provide qualifications to the instruction Lc (1
 *         byte): Number of bytes present in the data field of the command Data
 *         field (bytes equal to the value of Lc): A sequence of bytes in the
 *         data field of the command Le (1 byte): Maximum of bytes expected in
 *         the data field of the response to the command
 */

public class CardApplet extends javacard.framework.Applet implements ISO7816 {
	// Classes go here
	/** For encrypted instructions and responses */
	static final byte CLA_ENCRYPTED = (byte) 0x41;

	// Instructions go here
	/* Not yet issued */
	private static final byte INS_SET_ID = (byte) 0x00;
	private static final byte INS_ISSUE = (byte) 0x10;
	private static final byte INS_PIN_SET = (byte) 0x20;
	private static final byte INS_UNISSUE = (byte) 0x11;

	private static final byte INS_STORE_BACKEND_CERT = (byte) 0x40;
	private static final byte INS_STORE_CARD_CERT = (byte) 0x50;
	private static final byte INS_SET_CARD_PRIV_EXP = (byte) 0x51;
	private static final byte INS_SET_CARD_PUB_EXP = (byte) 0x52;
	private static final byte INS_SET_CARD_PRIV_MOD = (byte) 0x53;
	private static final byte INS_SET_CARD_PUB_MOD = (byte) 0x54;;
	private static final byte INS_SET_ROOT_PUB_EXP = (byte) 0x55;
	private static final byte INS_SET_ROOT_PUB_MOD = (byte) 0x56;
	/* Issued */
	private static final byte INS_PIN_VERIFY = (byte) 0x21;
	private static final byte INS_BALANCE_GET = (byte) 0x30;
	private static final byte INS_BALANCE_SUB = (byte) 0x31;
	private static final byte INS_BALANCE_INC = (byte) 0x32;

	private static final byte INS_SEND_ENC = (byte) 0x41;
	private static final byte INS_RECV_ENC = (byte) 0x42;
	private static final byte INS_SET_TERM_PUB_EXP = (byte) 0x43;
	private static final byte INS_SET_TERM_PUB_MOD = (byte) 0x44;
	private static final byte INS_SEND_SK = (byte) 0x45;

	private static final byte INS_RECV_VERIFY_TERM_CERT = (byte) 0xa0;

	// TODO This does leak information about where in the protocol things fail,
	// but it is nice for debugging to have it
	// Errors go here
	private final static short SW_WRONG_CERTIFICATE_LENGTH = 0x6a00;
	private final static short SW_WRONG_CERTIFICATE = 0x6a01;

	private final static short SW_WRONG_ORDER = 0x6123;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_WRONG_PIN_LENGTH = 0x6302;
	private final static short SW_WRONG_PIN = 0x6303;

	// Variables go here

	short lastUpdatedDay;
	short lastUpdatedMonth;
	short lastUpdatedYear;

	private static final byte STATE_INIT = (byte) 0x00;
	private static final byte STATE_ISSUED = (byte) 0x01;

	/** Temporary buffer */
	byte[] mutauthstate;
	byte[] tmp;
	byte[] work;

	/** The applet state (INIT or ISSUED). */
	byte state;

	/** Key for encryption. */
	RSAPublicKey pubKeyCard;

	/** Key for decryption. */
	RSAPrivateKey privKeyCard;

	/** Backend key for encryption */
	RSAPublicKey pubKeyBackEnd;

	/** Terminal key for encryption */
	RSAPublicKey pubKeyTerminal;

	/** RSA cipher for communication with terminal */
	Cipher cipherTerminal;
	
	/** DES Cipher for encryption and decryption. */
	Cipher cipher;

	/** Pincode */
	OwnerPIN pin;
	/**
	 * maximum number of incorrect tries before the PIN is blocked TODO How
	 * many?
	 */
	final static byte PinTryLimit = (byte) 0x03; // Careful this is a signed
													// value and negative will
													// prevent the applet from
													// installing
	/** maximum size PIN, in bytes */
	final static byte MaxPinSize = (byte) 0x02;

	/** Balance of the card, maximum of 32767 TODO: Higher */
	short cardBalance;

	/** Personal ID */
	byte[] id;

	/*
	 * This never really worked
	 *//**
	 * The root certificate, contains the root public key which we will need
	 * for certificate validation
	 */
	/*
	 * CVCertificate certificateRoot;
	 *//** Cards CVC Certificate, signed by the CA (Probably the back end) */
	/*
	 * CVCertificate certificateCard;
	 *//** During mutual authentication we will receive a terminal certificate */
	/*
	 * CVCertificate certificateTerminal;
	 *//** Symmetric key */
	/*
*/DESKey tripleDesKey;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new app.CardApplet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	/**
	 * Constructor at applet-install-time; creates the key-structure and sets
	 * the state to STATE_INIT this is the only time we can create new data
	 * structures, so make it count.
	 */
	public CardApplet() {
		/** Transient array in RAM to use for sensitive data */
		mutauthstate = JCSystem.makeTransientByteArray((short) 1,
				JCSystem.CLEAR_ON_DESELECT);
		tmp = JCSystem.makeTransientByteArray((short) 24,
				JCSystem.CLEAR_ON_DESELECT);
		/** Temporary storage for receiving keys and the like */
		work = JCSystem.makeTransientByteArray((short) 256,
				JCSystem.CLEAR_ON_DESELECT);
		// tmp[0] = mutualAuthProtStep
		// tmp[1..17] = randomdata (for session key)

		/** Card will establish a session key, store here */
		// cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1_OAEP,false);

		/** Things in EEPROM */
		/** When the applet is installed the state is STATE_INIT */
		state = STATE_INIT;
		/** The triple des key */
		tripleDesKey = (DESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_DES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_DES3_3KEY, false);
		/**
		 * Public key of the card, this should be in a X509/CVC structure. But I
		 * don't know how that works yet
		 */
		pubKeyCard = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		/** Cards own private key */
		privKeyCard = (RSAPrivateKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		/** Public key of the back end, this should eventually be in a CVCert. */
		pubKeyBackEnd = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		/**
		 * Public key for the terminal we receive during mutual auth, it should
		 * be in a CVCert but technical issues
		 */
		pubKeyTerminal = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		cipherTerminal = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
		/** Owner unique code, managed by the backend which will issue IDs */
		byte[] id = new byte[8];
		/** The revocation list */
		// TODO
		/** The pin structure */
		pin = new OwnerPIN(PinTryLimit, MaxPinSize);
		/** Initial balance is zero */
		cardBalance = (short) 0x1337;
		/** Logging? */
		// Log log = new log;
		/** Certificates, never got them working */
		// certificateRoot = new CVCertificate();
		// certificateCard = new CVCertificate();
		// certificateTerminal = new CVCertificate();
		lastUpdatedDay = (short) 0;
		lastUpdatedMonth = (short) 0;
		lastUpdatedYear = (short) 0;
	}

	public void deselect() {
		/**
		 * If pin was validated this resets the validation and counter, else
		 * does nothing
		 */
		pin.reset();
	}

	public boolean select() {
		/** Decline selection if blocked */
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		byte[] buffer = apdu.getBuffer();
		// Class
		short cla = (short) (buffer[OFFSET_CLA] & 0x00FF); 
		if((short) cla == CLA_ENCRYPTED){
			recvEnc(apdu);
		}
		// Instruction
		short ins = (short) (buffer[OFFSET_INS] & 0x00FF);
		// len(data)
	    short lc = (short)(buffer[OFFSET_LC] & 0x00FF);

		short outLength;

        //boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        
		if (selectingApplet()) {
			return;
		}
	  
		switch(state) {
		/* The card is not yet initialized, there will need to be support for:
		 * - Uploading key material
		 * - Uploading card identification
		 * - Set pin code
		 * - (Register to car owner)
		 * - Setting the state to issued.
		 */
		case STATE_INIT:
			switch(ins){
			case INS_SET_ROOT_PUB_EXP:
				readBuffer(apdu,work,(short)0,lc);
				pubKeyBackEnd.setExponent(work,(short)0,lc);
				break;
			case INS_SET_ROOT_PUB_MOD:
				readBuffer(apdu,work,(short)0,lc);
				pubKeyBackEnd.setModulus(work,(short)0,lc);
				break;
			case INS_SET_CARD_PRIV_EXP:
				readBuffer(apdu,work,(short)0,lc);
				privKeyCard.setExponent(work,(short)0,lc);
				break;
			case INS_SET_CARD_PUB_EXP:
				readBuffer(apdu,work,(short)0,lc);
				pubKeyCard.setExponent(work,(short)0,lc);
				break;
			case INS_SET_CARD_PRIV_MOD:
				readBuffer(apdu,work,(short)0,lc);
				privKeyCard.setModulus(work,(short)0,lc);
				break;
			case INS_SET_CARD_PUB_MOD:
				readBuffer(apdu,work,(short)0,lc);
				pubKeyCard.setModulus(work,(short)0,lc);
				break;
			case INS_SET_ID:
				readBuffer(apdu,work,(short)0,lc);
				Util.arrayCopy(work, (short)0, id, (short)0, lc);
				break;
			/** Receive and store card certificate */
/*			case INS_STORE_CARD_CERT:
                readBuffer(apdu,tmp,(short)0,lc);
				setCardCertificate(tmp, lc);
				break;*/
/*			*//** During initialization we receive the back-end (r00t) certificate, to verify terminal certificates with *//*
			case INS_STORE_BACKEND_CERT:
                readBuffer(apdu,tmp,(short)0,lc);
				setBackEndCert(tmp, lc);
				break;*/
			/** Set the pin */
			case INS_PIN_SET:
				setPin(apdu);
				break;
			/** Issue the card, can not be undone */
			case INS_ISSUE:
				issueCard();
				break;
			default:
				ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			}
			break;
		/* The card has been initialized, all the key material is assumed to be present.
		 * Support for:
		 * Charging terminal:
		 * - Validate card
		 * - PIN validation
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
		case STATE_ISSUED:
			switch(ins) {
			case INS_SET_TERM_PUB_EXP:
				if(mutauthstate[0] == (short)0){
					readBuffer(apdu,work,(short)0,lc);
					pubKeyTerminal.setExponent(work,(short)0,lc);
					mutauthstate[0] += 1;
				}
				else ISOException.throwIt(SW_WRONG_ORDER);
				break;
			case INS_SET_TERM_PUB_MOD:
				if(mutauthstate[0] == (short)1){
					readBuffer(apdu,work,(short)0,lc);
					pubKeyBackEnd.setModulus(work,(short)0,lc);
					mutauthstate[0] += 1;
				}
				else ISOException.throwIt(SW_WRONG_ORDER);
				break;
			case INS_SEND_SK:
				byte[] buf = apdu.getBuffer();
				readBuffer(apdu,work,(short)0,lc);
				RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				rng.generateData(tmp,(short)0,(short)24);
				tripleDesKey.setKey(tmp, (short) 0);
				apdu.setOutgoing();
				cipherTerminal.init(pubKeyTerminal,Cipher.MODE_ENCRYPT);
				outLength = cipher.doFinal(tmp,(short)0,lc,buf,(short)0);
				// TODO Also send our public key encrypted with the deskey and sign this stuff
				apdu.setOutgoingLength(outLength);
				apdu.sendBytes((short)0,outLength);
				break;
			case INS_PIN_VERIFY:
				pin_verify(apdu);
				break;
			case INS_UNISSUE:
				unIssueCard();
				break;
			case INS_BALANCE_GET:
				getBalance(apdu);
				break;
			case INS_BALANCE_SUB:
				subBalance(apdu);
				break;
			case INS_BALANCE_INC:
				incBalance(apdu);
				break;
/*			case INS_RECV_VERIFY_TERM_CERT:
				receiveAndVerifyTermCert(apdu);
				break;*/
			case INS_SEND_ENC:
				sendEnc(apdu);
				break;
			case INS_RECV_ENC:
				recvEnc(apdu);
				break;
			default:
		
				ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			}
			break;
		}
	}

	private void sendSk(APDU apdu) {

		return;
	}

	/**
	 * Receive an encrypted APDU data, decrpyt it with the Key and pass back the
	 * decrypted bytes
	 */
	private void recvEnc(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte byteRead = (byte) (apdu.setIncomingAndReceive());
		byte[] testkey = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		tripleDesKey.setKey(testkey, (short) 0x00);
		// Using padding always gives errors
		cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, true);
		cipher.init(tripleDesKey, Cipher.MODE_DECRYPT, new byte[] { (byte) 0,
				(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
				(byte) 0 }, (short) 0, (short) 8);
		cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, (short) byteRead,
				work, (short) 0);
		Util.arrayCopy(work, (short) 0, buffer, (short) 0, byteRead);
		apdu.setOutgoing();
		apdu.setOutgoingLength(byteRead);
		apdu.sendBytes((short) 0, byteRead);
		return;
	}

	private void sendEnc(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		// check length
		byte[] testkey = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

		byte[] testplain = { (byte) 'H', (byte) 'e', (byte) 'l', (byte) 'l',
				(byte) 'o', (byte) ' ', (byte) 'W', (byte) 'o', (byte) 'u',
				(byte) 't', (byte) 'e', (byte) 'r', (byte) '!', (byte) '!',
				(byte) '!', (byte) 0x0a, };
		byte[] testct = new byte[16];

		tripleDesKey.setKey(testkey, (short) 0x00);
		cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		cipher.init(tripleDesKey, Cipher.MODE_ENCRYPT, new byte[] { (byte) 0,
				(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
				(byte) 0 }, (short) 0, (short) 8);
		cipher.doFinal(testplain, (short) 0, (short) 16, testct, (short) 0);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 16);

		Util.arrayCopy(testct, (short) 0, buffer, (short) 0, (short) 16);
		apdu.sendBytes((short) 0, (short) 16);
		return;
	}

	private void incBalance(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if (byteRead != (byte) 8)
			ISOException.throwIt((short) 0xabcd);
		// get the amount and date from the buffer
		short s = Util.getShort(buffer, (short) ISO7816.OFFSET_CDATA);
		short day = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
		short month = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 4));
		short year = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6));
		// check date against something
		if (month <= lastUpdatedMonth && year <= lastUpdatedYear)
			ISOException.throwIt((short) 0xdead);
		if (s + cardBalance < cardBalance)
			ISOException.throwIt((short) 0x1234);
		JCSystem.beginTransaction();
		cardBalance = (short) (cardBalance + s);
		lastUpdatedYear = year;
		lastUpdatedMonth = month;
		lastUpdatedDay = day;
		JCSystem.commitTransaction();
		return;
	}

	private void subBalance(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if (byteRead != (byte) 2)
			ISOException.throwIt((short) 0xabcd);

		// get the amount from the buffer
		short s = 0;
		s = Util.getShort(buffer, (short) ISO7816.OFFSET_CDATA);
		if (s < (short) 0)
			ISOException.throwIt((short) 0x1234);
		if (s > cardBalance)
			ISOException.throwIt((short) 0x1234);
		cardBalance = (short) (cardBalance - s);
		return;
	}

	/*
	 * private void setBackEndCert(byte[] in, short lc) { // we will receive
	 * ~1126 bytes of certificate, all the while copying it into the designated
	 * certroot array
	 *//** This is the root certificate for the system" */
	/*
	 * Util.arrayCopyNonAtomic(in, (short)0, certroot, (short) 0, lc);
	 * certificateRoot.parseCertificate(in, (short)0, lc, true); pubKeyBackEnd =
	 * certificateCard.currentCertPublicKey; return; }
	 */

	/**
	 * During mutual authentication we receive a certificate, we shall verify
	 * that this certificate is signed by the CA. We can then use the public key
	 * from this certificate for the mutual authentication protocol.
	 */
	/*
	 * private void receiveAndVerifyTermCert(APDU apdu) { byte[] buffer =
	 * apdu.getBuffer(); short buffer_p = (short) (OFFSET_CDATA & 0xff); byte
	 * byteRead = (byte)(apdu.setIncomingAndReceive());
	 *//** Card certificate is signed by the "Overall System acting as CA" */
	/*
	 * certificateTerminal.parseCertificate(buffer, buffer_p, byteRead, false);
	 * // Somehow set the public key to be used for verification
	 * certificateTerminal.setRootCertificate(certroot, (short)1); //TODO
	 * certificates are hard =/ // Idea: store the byte[] of certificateRoot
	 * only... we might not need to parse it... ever... maybe // Do the actual
	 * signature verification if(!certificateTerminal.verify()){
	 * ISOException.throwIt(SW_WRONG_CERTIFICATE); }
	 * 
	 * return; }
	 */
	private void getBalance(APDU apdu) {
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		short le = apdu.setOutgoing();
		if (le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// informs the CAD the actual number of bytes returned
		apdu.setOutgoingLength((byte) 2);

		// move the balance data into the APDU buffer
		// starting at the offset 0
		buffer[0] = (byte) (cardBalance >> 8);
		buffer[1] = (byte) (cardBalance & 0xFF);
		// send the 2-balance byte at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short) 0, (short) 2);
		return;
	}

	private void pin_verify(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data to validate.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// Die if PinSize is not correct (information leak?)
		if (byteRead != MaxPinSize) {
			ISOException.throwIt(SW_WRONG_PIN_LENGTH);
		}
		// Set the pin to the value in the data field
		if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead)) {
			return;
		}
		ISOException.throwIt(SW_WRONG_PIN);
	}

	private void setID() {
		// TODO Auto-generated method stub
	}

	/** For debugging purposes. */
	private void unIssueCard() {
		state = STATE_INIT;
		return;
	}

	private void issueCard() {
		state = STATE_ISSUED;
		return;
	}

	/** Set the cards own CVC certificate during initialization */

	/*
	 * private void setCardCertificate(byte[] in, short lc) {
	 *//** This is the cards personal certificate, signed by the backend" */
	/*
	 * certificateCard.parseCertificate(in, (short)0, lc, false);
	 * certificateCard.setRootCertificate(certroot, (short)1); //what does this
	 * 1 mean?? pubKeyCard = certificateCard.currentCertPublicKey; return;
	 * //certroot = buffer; }
	 */

	// Could also be done at install-time
	/** Sets the PIN code of a card */
	private void setPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// Die if PinSize is not correct
		if (byteRead != MaxPinSize) {
			ISOException.throwIt(SW_WRONG_PIN_LENGTH);
		}
		// Set the pin to the value in the data field
		pin.update(buffer, ISO7816.OFFSET_CDATA, byteRead);
		return;
	}

	/**
	 * Copies <code>length</code> bytes of data (starting at
	 * <code>OFFSET_CDATA</code>) from <code>apdu</code> to <code>dest</code>
	 * (starting at <code>offset</code>).
	 * 
	 * This method will set <code>apdu</code> to incoming.
	 * 
	 * @param apdu
	 *            the APDU.
	 * @param dest
	 *            destination byte array.
	 * @param offset
	 *            offset into the destination byte array.
	 * @param length
	 *            number of bytes to copy.
	 */
	private void readBuffer(APDU apdu, byte[] dest, short offset, short length) {
		byte[] buf = apdu.getBuffer();
		short readCount = apdu.setIncomingAndReceive();
		short i = 0;
		Util.arrayCopy(buf, OFFSET_CDATA, dest, offset, readCount);
		while ((short) (i + readCount) < length) {
			i += readCount;
			offset += readCount;
			readCount = (short) apdu.receiveBytes(OFFSET_CDATA);
			Util.arrayCopy(buf, OFFSET_CDATA, dest, offset, readCount);
		}
	}
} // End of class