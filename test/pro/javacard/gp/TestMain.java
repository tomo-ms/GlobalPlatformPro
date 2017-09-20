package pro.javacard.gp;

import java.util.List;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;

import apdu4j.HexUtils;

public class TestMain {

	private static final BerTag GP_REGISTRY_TAG = new BerTag(0xE3);
	private static final BerTag APP_AID_TAG = new BerTag(0x4F);
	private static final BerTag LIFECYCLE_TAG = new BerTag(0x9F, 0x70);
	private static final BerTag PRIVILEGES_TAG = new BerTag(0xC5);
	private static final BerTag SELECTION_PARAM_TAG = new BerTag(0xCF);
	private static final BerTag ELF_AID_TAG = new BerTag(0xC4);
	private static final BerTag SD_AID_TAG = new BerTag(0xCC);
	private static final BerTag ELF_VER_TAG = new BerTag(0xCE);
	private static final BerTag MODULE_AID_TAG = new BerTag(0x84);


	public static void main(String[] args) {
		byte[] data = HexUtils.hex2bin("E3464F08A0000000030000009F700101C5039EFE80CF0140CF0141CF0142CF0143CF0180CF0181CF0182CF0183C40BD276000005AAFFCAFE0001CE020001CC08A000000003000000");
		BerTlvParser parser = new BerTlvParser();
		BerTlvs tlvs = parser.parse(data);
		System.out.println(tlvs.getList());
		List<BerTlv> tlvsList = tlvs.getList();
		for( BerTlv tlv : tlvsList) {
			if ( tlv.getTag().equals(GP_REGISTRY_TAG) ) {
				List<BerTlv> elems = tlv.getValues();
				for(BerTlv elem : elems) {
					if (elem.getTag().equals(APP_AID_TAG)) {
						AID aid = new AID(elem.getBytesValue());
						System.out.println(String.format("AID %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						//						app.setAID(aid);
						//						pkg.setAID(aid);
					} else if (elem.getTag().equals(PRIVILEGES_TAG)) {
						System.out.println(String.format("Priv %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						// privileges
						//						Privileges privs = Privileges.fromBytes(value.getBytesValue());
						//						app.setPrivileges(privs);
					} else if (elem.getTag().equals(ELF_AID_TAG)) {
						System.out.println(String.format("ELF %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						AID a = new AID(elem.getBytesValue());
						//						app.setLoadFile(a);
					} else if (elem.getTag().equals(SD_AID_TAG)) {
						System.out.println(String.format("SD %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						AID a = new AID(elem.getBytesValue());
						//						app.setDomain(a);
						//						pkg.setDomain(a);
					} else if (elem.getTag().equals(ELF_VER_TAG)) {
						System.out.println(String.format("ELF Ver %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						//						pkg.setVersion(value.getBytesValue());
					} else if (elem.getTag().equals(LIFECYCLE_TAG)) { // lifecycle
						System.out.println(String.format("Life cycle %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						byte val = elem.getBytesValue()[0];
						//						ASN1OctetString lc = DEROctetString.getInstance(tag, false);
						//						app.setLifeCycle(lc.getOctets()[0] & 0xFF);
						//						pkg.setLifeCycle(lc.getOctets()[0] & 0xFF);
					} else if (elem.getTag().equals(MODULE_AID_TAG)) { // Executable module AID
						System.out.println(String.format("Module %s -> %s", elem.getTag().toString(), elem.getHexValue()));
						//						ASN1OctetString lc = DEROctetString.getInstance(tag, false);
						AID a = new AID(elem.getBytesValue());
						//						pkg.addModule(a);
					} else if (elem.getTag().equals(SELECTION_PARAM_TAG)) { // Executable module AID
						System.out.println(String.format("Param %s -> %s", elem.getTag().toString(), elem.getHexValue()));
					} else {
						// XXX there are cards that have unknown tags.
						// Normally we'd like to avoid having proprietary data
						// but the rest of the response parses OK. So just ignore these
						// tags instead of throwing an exception
						//						logger.warn("Unknown data: " + HexUtils.bin2hex(value.getTag().bytes));
					}
				}
			}
		}
	}

}
