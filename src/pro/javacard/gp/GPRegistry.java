/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;

import apdu4j.HexUtils;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GlobalPlatform.GPSpec;

/**
 * Convenience class managing a vector of {@link GPRegistryEntry
 * AIDRegistryEntries} with search functionality.
 *
 * Implements {@code Iterable<GPRegistryEntry} to permit foreach loops such as
 * {@code for(GPRegistryEntry e : registry) ...}.
 */
public class GPRegistry implements Iterable<GPRegistryEntry> {
	private static Logger logger = LoggerFactory.getLogger(GPRegistry.class);
	boolean tags = true; // XXX (visibility) true if newer tags format should be used for parsing, false otherwise
	LinkedHashMap<AID, GPRegistryEntry> entries = new LinkedHashMap<AID, GPRegistryEntry>();

	private static final BerTag GP_REGISTRY_TAG = new BerTag(0xE3);
	private static final BerTag APP_AID_TAG = new BerTag(0x4F);
	private static final BerTag LIFECYCLE_TAG = new BerTag(0x9F, 0x70);
	private static final BerTag PRIVILEGES_TAG = new BerTag(0xC5);
	private static final BerTag SELECTION_PARAM_TAG = new BerTag(0xCF);
	private static final BerTag ELF_AID_TAG = new BerTag(0xC4);
	private static final BerTag SD_AID_TAG = new BerTag(0xCC);
	private static final BerTag ELF_VER_TAG = new BerTag(0xCE);
	private static final BerTag MODULE_AID_TAG = new BerTag(0x84);

	/**
	 * Add one entry to this registry.
	 *
	 * @param entry
	 */
	public void add(GPRegistryEntry entry) {
		// "fix" the kind at a single location.
		if (entry instanceof GPRegistryEntryApp) {
			GPRegistryEntryApp app = (GPRegistryEntryApp) entry;
			if (app.getPrivileges().has(Privilege.SecurityDomain) && entry.getType() == Kind.Application) {
				entry.setType(Kind.SecurityDomain);
			}
		}
		// XXX Legacy, combined with logic in GlobalPlatform.getStatus()
		GPRegistryEntry existing = entries.get(entry.getAID());
		if (existing != null && existing.getType() != entry.getType()) {
			// OP201 cards list the ISD AID as load file.
			return;
		}
		entries.put(entry.getAID(), entry);
	}

	/**
	 * Returns an iterator that iterates over all entries in this registry.
	 *
	 * @return iterator
	 */
	public Iterator<GPRegistryEntry> iterator() {
		return entries.values().iterator();
	}


	/**
	 * Returns a list of all packages in this registry.
	 *
	 * @return a list of all packages
	 */
	public List<GPRegistryEntryPkg> allPackages() {
		List<GPRegistryEntryPkg> res = new ArrayList<GPRegistryEntryPkg>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isPackage()) {
				res.add((GPRegistryEntryPkg)e);
			}
		}
		return res;
	}

	public List<AID> allPackageAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isPackage()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAppletAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isApplet()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			res.add(e.getAID());
		}
		return res;
	}
	/**
	 * Returns a list of all applets in this registry.
	 *
	 * @return a list of all applets
	 */
	public List<GPRegistryEntryApp> allApplets() {
		List<GPRegistryEntryApp> res = new ArrayList<GPRegistryEntryApp>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isApplet()) {
				res.add((GPRegistryEntryApp)e);
			}
		}
		return res;
	}

	public AID getDefaultSelectedAID() {
		for (GPRegistryEntryApp e : allApplets()) {
			if (e.getPrivileges().has(Privilege.CardReset)) {
				return e.getAID();
			}
		}
		return null;
	}

	public AID getDefaultSelectedPackageAID() {
		AID defaultAID = getDefaultSelectedAID();
		if (defaultAID != null) {
			for (GPRegistryEntryPkg e : allPackages()) {
				if (e.getModules().contains(defaultAID))
					return e.getAID();
			}
			// Did not get a hit. Loop packages and look for prefixes
			for (GPRegistryEntryPkg e : allPackages()) {
				if (defaultAID.toString().startsWith(e.getAID().toString()))
					return e.getAID();
			}
		}
		return null;
	}

	// Shorthand
	public GPRegistryEntryApp getISD() {
		for (GPRegistryEntryApp a: allApplets()) {
			if (a.getType() == Kind.IssuerSecurityDomain) {
				return a;
			}
		}
		// Could happen if the registry is a view from SSD
		return null;
	}

	private void populate_legacy(int p1, byte[] data, Kind type, GPSpec spec) throws GPDataException {
		int offset = 0;
		try {
			while (offset < data.length) {
				int len = data[offset++];
				AID aid = new AID(data, offset, len);
				offset += len;
				int lifecycle = (data[offset++] & 0xFF);
				byte privileges = data[offset++];

				if (type == Kind.IssuerSecurityDomain || type == Kind.Application) {
					GPRegistryEntryApp app = new GPRegistryEntryApp();
					app.setType(type);
					app.setAID(aid);
					app.setPrivileges(Privileges.fromByte(privileges));
					app.setLifeCycle(lifecycle);
					add(app);
				} else if (type == Kind.ExecutableLoadFile) {
					if (privileges != 0x00) {
						throw new GPDataException("Privileges of Load File is not 0x00");
					}
					GPRegistryEntryPkg pkg = new GPRegistryEntryPkg();
					pkg.setAID(aid);
					pkg.setLifeCycle(lifecycle);
					pkg.setType(type);
					// Modules TODO: remove
					if (spec != GPSpec.OP201 && p1 != 0x20) {
						int num = data[offset++];
						for (int i = 0; i < num; i++) {
							len = data[offset++] & 0xFF;
							aid = new AID(data, offset, len);
							offset += len;
							pkg.addModule(aid);
						}
					}
					add(pkg);
				}
			}
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new GPDataException("Invalid response to GET STATUS", e);
		}
	}

	private void populate_tags(byte[] data, Kind type) throws GPDataException {
		BerTlvParser parser = new BerTlvParser();
		BerTlvs tlvs = parser.parse(data);
		List<BerTlv> tlvsList = tlvs.getList();
		for( BerTlv tlv : tlvsList) {
			if ( tlv.getTag().equals(GP_REGISTRY_TAG) ) {
				GPRegistryEntryApp app = new GPRegistryEntryApp();
				GPRegistryEntryPkg pkg = new GPRegistryEntryPkg();
				List<BerTlv> elems = tlv.getValues();
				for(BerTlv elem : elems) {
					if (elem.getTag().equals(APP_AID_TAG)) {
						AID aid = new AID(elem.getBytesValue());
						app.setAID(aid);
						pkg.setAID(aid);
					} else if (elem.getTag().equals(PRIVILEGES_TAG)) {
						// privileges
						Privileges privs = Privileges.fromBytes(elem.getBytesValue());
						app.setPrivileges(privs);
					} else if (elem.getTag().equals(ELF_AID_TAG)) {
						AID a = new AID(elem.getBytesValue());
						app.setLoadFile(a);
					} else if (elem.getTag().equals(SD_AID_TAG)) {
						AID a = new AID(elem.getBytesValue());
						app.setDomain(a);
						pkg.setDomain(a);
					} else if (elem.getTag().equals(ELF_VER_TAG)) {
						pkg.setVersion(elem.getBytesValue());
					} else if (elem.getTag().equals(LIFECYCLE_TAG)) { // lifecycle
						byte val = elem.getBytesValue()[0];
						app.setLifeCycle(val);
						pkg.setLifeCycle(val);
					} else if (elem.getTag().equals(MODULE_AID_TAG)) { // Executable module AID
						AID a = new AID(elem.getBytesValue());
						pkg.addModule(a);
					} else if (elem.getTag().equals(SELECTION_PARAM_TAG)) { //  Implicit Selection Parameter
						// Ignore
					} else {
						// XXX there are cards that have unknown tags.
						// Normally we'd like to avoid having proprietary data
						// but the rest of the response parses OK. So just ignore these
						// tags instead of throwing an exception
						logger.warn("Unknown data: " + HexUtils.bin2hex(elem.getTag().bytes));
					}
				}
				// Construct entry
				if (type == Kind.ExecutableLoadFile) {
					pkg.setType(type);
					add(pkg);
				} else {
					app.setType(type);
					add(app);
				}
			} else {
				throw new GPDataException("Invalid tag", tlv.getTag().bytes);
			}
		}
	}

	// FIXME: this is ugly
	public void parse(int p1, byte[] data, Kind type, GPSpec spec) throws GPDataException {
		if (tags) {
			populate_tags(data, type);
		} else {
			populate_legacy(p1, data, type, spec);
		}
	}
}
