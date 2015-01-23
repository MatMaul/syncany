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

import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;
import org.simpleframework.xml.convert.Convert;
import org.simpleframework.xml.convert.Registry;
import org.simpleframework.xml.convert.RegistryStrategy;
import org.simpleframework.xml.core.Persister;
import org.simpleframework.xml.strategy.Strategy;
import org.syncany.config.ConfigException;
import org.syncany.crypto.MasterKey;
import org.syncany.crypto.MasterKeyConverter;
import org.syncany.plugins.transfer.EncryptedTransferSettingsConverter;
import org.syncany.plugins.transfer.TransferSettings;

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
@Root(name = "config", strict = false)
public class ConfigTO {
	@Element(name = "machineName", required = true)
	private String machineName;

	@Element(name = "displayName", required = false)
	private String displayName;

	@Element(name = "masterKey", required = false)
	@Convert(MasterKeyConverter.class)
	private MasterKey masterKey;

	@Element(name = "connection", required = false) // TODO [high] Workaround for 'connect' via GUI and syncany://link; field not needed when link is supplied
	private TransferSettings transferSettings;

	@Element(name = "cacheKeepBytes", required = false)
	private Long cacheKeepBytes;

	public static ConfigTO load(File file) throws ConfigException {
		try {
			return new ConfigTO().createPersister().read(ConfigTO.class, file);
		}
		catch (Exception ex) {
			throw new ConfigException("Config file does not exist or is invalid: " + file, ex);
		}
	}

	public Persister createPersister() throws Exception {
		Registry registry = new Registry();
		Strategy strategy = new RegistryStrategy(registry);
		registry.bind(MasterKey.class, new MasterKeyConverter());
		if (transferSettings == null) {
			registry.bind(String.class, new EncryptedTransferSettingsConverter());
		} else {
			registry.bind(String.class, new EncryptedTransferSettingsConverter(transferSettings.getClass()));
		}
		return new Persister(strategy);
	}

	public void save(File file) throws ConfigException {
		try {
			Registry registry = new Registry();
			Strategy strategy = new RegistryStrategy(registry);
			registry.bind(MasterKey.class, new MasterKeyConverter());
			registry.bind(String.class, new EncryptedTransferSettingsConverter(transferSettings.getClass()));

			new Persister(strategy).write(this, file);
		}
		catch (Exception e) {
			throw new ConfigException("Cannot write config to file " + file, e);
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

	public TransferSettings getTransferSettings() {
		return transferSettings;
	}

	public void setTransferSettings(TransferSettings transferSettings) {
		this.transferSettings = transferSettings;
	}

	public MasterKey getMasterKey() {
		return masterKey;
	}

	public void setMasterKey(MasterKey masterKey) {
		this.masterKey = masterKey;
	}

	public Long getCacheKeepBytes() {
		return cacheKeepBytes;
	}

	public void setCacheKeepBytes(Long cacheKeepBytes) {
		this.cacheKeepBytes = cacheKeepBytes;
	}

}
