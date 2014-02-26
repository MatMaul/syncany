/*
 * Syncany, www.syncany.org
 * Copyright (C) 2011-2014 Philipp C. Heckel <philipp.heckel@gmail.com> 
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.syncany.config.to;

import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.Namespace;
import org.simpleframework.xml.Root;
import org.simpleframework.xml.core.Commit;
import org.simpleframework.xml.core.Complete;
import org.simpleframework.xml.core.Persist;
import org.simpleframework.xml.core.Persister;
import org.syncany.config.Config.ConfigException;
import org.syncany.crypto.MasterKey;
import org.syncany.util.StringUtil;

/**
 * The config transfer object is used to create and load the local config
 * file from/to XML. The config file contains local config settings of a client,
 * namely the machine and display name, the master key as well as connection
 * information (for the connection plugin).
 * 
 * <p>It uses the Simple framework for XML serialization, and its corresponding
 * annotation-based configuration.  
 *  
 * @see <a href="http://simple.sourceforge.net/">Simple framework</a> at simple.sourceforge.net
 * @author Philipp C. Heckel <philipp.heckel@gmail.com>
 */
@Root(name="config")
@Namespace(reference="http://syncany.org/config/1")
public class ConfigTO {
	@Element(name="machinename", required=true)
	private String machineName;

	@Element(name="displayname", required=false)
	private String displayName; 

	@Element(name="encryptkey", required=false)
	private String encryptKeyEncoded;

	@Element(name="salt", required=false)
	private String saltEncoded;

	@Element(name="signingkey", required=false)
	private String signingKeyEncoded;

	private MasterKey masterKey;


	@Element(name="connection", required=true)
	private ConnectionTO connectionTO;

	public static ConfigTO load(File file) throws ConfigException {
		try {
			return new Persister().read(ConfigTO.class, file);
		}
		catch (Exception ex) {
			throw new ConfigException("Config file does not exist or is invalid: " + file, ex);
		}
	}

	public String getMachineName() {
		return machineName;
	}

	public void setMachineName(String machineName) {
		this.machineName = machineName;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public ConnectionTO getConnectionTO() {
		return connectionTO;
	}

	public void setConnection(ConnectionTO connectionTO) {
		this.connectionTO = connectionTO;
	}

	public MasterKey getMasterKey() {
		return masterKey;
	}

	public void setMasterKey(MasterKey masterKey) {
		this.masterKey = masterKey;
	}

	@Persist
	public void prepare() {
		if (masterKey != null) {
			encryptKeyEncoded = StringUtil.toHex(masterKey.getEncryptKey().getEncoded());
			if (masterKey.getSigningKey() != null) {
				signingKeyEncoded = StringUtil.toHex(masterKey.getSigningKey().getEncoded());
			} else {
				signingKeyEncoded = null;
			}
			saltEncoded = StringUtil.toHex(masterKey.getSalt());
		}
		else {
			encryptKeyEncoded = null;
			signingKeyEncoded = null;
			saltEncoded = null;
		}
	}

	@Complete
	public void release() {
		encryptKeyEncoded = null;
		signingKeyEncoded = null;
		saltEncoded = null;
	}

	@Commit
	public void commit() {
		if (encryptKeyEncoded != null && !"".equals(encryptKeyEncoded)) {
			SecretKey signingKey = null;
			if (signingKeyEncoded != null && !"".equals(signingKeyEncoded)) {
				signingKey = decodeKey(signingKeyEncoded);
			}
			SecretKey encryptKey = decodeKey(encryptKeyEncoded);
			masterKey = new MasterKey(encryptKey, StringUtil.fromHex(saltEncoded), signingKey);
		} else {
			masterKey = null;
		}
	}

	private static SecretKey decodeKey(String key) {
		byte[] keyBytes = StringUtil.fromHex(key);

		return new SecretKeySpec(keyBytes, "RAW");
	}

	public static class ConnectionTO extends TypedPropertyListTO {
		// Nothing special about this
	}
}
