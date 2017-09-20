package pro.javacard.gp;


public enum StatusWord {
	SW_9000(0x90, 0x00,"Command successfully executed"),
	SW_6200(0x62, 0x00,"State of non-volatile memory unchanged"),
	SW_6281(0x62, 0x81,"Part of returned data may be corrupted"),
	SW_6282(0x62, 0x82,"End of file/record reached before reading Le bytes"),
	SW_6283(0x62, 0x83,"Selected file invalidated"),
	SW_6284(0x62, 0x84,"FCI not formatted according to 1.1.5"),
	SW_6300(0x63, 0x00,"State of non-volatile memory changed"),
	SW_6381(0x63, 0x81,"File filled up by the last write"),
	SW_63CX(0x63, 0xCF,"Counter provided by '0' "),
	SW_6400(0x64, 0x00,"State of non-volatile memory unchanged"),
	SW_6500(0x65, 0x00,"State of non-volatile memory changed"),
	SW_6581(0x65, 0x81,"Memory failure"),
	SW_6700(0x67, 0x00,"Wrong length"),
	SW_6800(0x68, 0x00,"Functions in CLA not supported"),
	SW_6881(0x68, 0x81,"Logical channel not supported"),
	SW_6882(0x68, 0x82,"Secure messaging not supported"),
	SW_6900(0x69, 0x00,"Command not allowed"),
	SW_6981(0x69, 0x81,"Command incompatible with file structure"),
	SW_6982(0x69, 0x82,"Security status not satisfied"),
	SW_6983(0x69, 0x83,"Authentication method blocked"),
	SW_6984(0x69, 0x84,"Referenced data invalidated"),
	SW_6985(0x69, 0x85,"Conditions of use not satisfied"),
	SW_6986(0x69, 0x86,"Command not allowed (no current EF)"),
	SW_6987(0x69, 0x87,"Expected SM data objects missing"),
	SW_6988(0x69, 0x88,"SM data objects incorrect"),
	SW_6A00(0x6A, 0x00,"Wrong parameter(s) P1-P2 "),
	SW_6A80(0x6A, 0x80,"Incorrect parameters in the data field"),
	SW_6A81(0x6A, 0x81,"Function not supported"),
	SW_6A82(0x6A, 0x82,"File not found"),
	SW_6A83(0x6A, 0x83,"Record not found"),
	SW_6A84(0x6A, 0x84,"Not enough memory space in the file"),
	SW_6A85(0x6A, 0x85,"Lc inconsistent with TLV structure"),
	SW_6A86(0x6A, 0x86,"Incorrect parameters P1-P2"),
	SW_6A87(0x6A, 0x87,"Lc inconsistent with P1-P2"),
	SW_6A88(0x6A, 0x88,"Referenced data not found"),
	SW_6B00(0x6B, 0x00,"Wrong parameter(s) P1-P2"),
	SW_6CXX(0x6C, 0xFF,"Wrong length Le"),
	SW_6D00(0x6D, 0x00,"Instruction code not supported or invalid"),
	SW_6E00(0x6E, 0x00,"Class not supported"),
	SW_6F00(0x6F, 0x00,"No precise diagnostics");

	public final int sw1;
	public final int sw2;
	private final String description;


	private StatusWord(int sw1, int sw2, String description) {
		this.sw1 = sw1;
		this.sw2 = sw2;
		this.description = description;
	}

	private boolean match(int sw1, int sw2) {
		if (this == StatusWord.SW_63CX) {
			if ( (this.sw1 == sw1) && ((this.sw2&0xF0) == (sw2&0xF0)))
				return true;
			else
				return false;
		} else if (this == StatusWord.SW_6CXX) {
			if ( this.sw1 == sw1)
				return true;
			else
				return false;
		} else {
			if ( (this.sw1 == sw1) && (this.sw2 == sw2) )
				return true;
			else
				return false;
		}
	}

	public static StatusWord getStatusWord(int sw1, int sw2) {
		for (StatusWord sw : values()) {
			if (sw.match(sw1, sw2))
				return sw;
		}
		return null;
	}


	public static String getDescription(int sw1, int sw2) {
		StatusWord sw = getStatusWord(sw1, sw2);
		if (sw == null)
			return null;
		else
			return sw.description;
	}
}
