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
package org.syncany.operations.init;

import java.io.File;

import org.syncany.config.to.ConfigTO;
import org.syncany.operations.OperationOptions;

/**
 * @author matmaul
 *
 */
public class AbstractInitOperationOptions implements OperationOptions {
	private File localDir;
	private ConfigTO configTO;
	private String encryptPassword;
	private String signPassword;
	private boolean daemon;

	public File getLocalDir() {
		return localDir;
	}

	public void setLocalDir(File localDir) {
		this.localDir = localDir;
	}

	public ConfigTO getConfigTO() {
		return configTO;
	}

	public void setConfigTO(ConfigTO configTO) {
		this.configTO = configTO;
	}

	public String getEncryptPassword() {
		return encryptPassword;
	}

	public void setEncryptPassword(String encryptPassword) {
		this.encryptPassword = encryptPassword;
	} 

	public String getSignPassword() {
		return signPassword;
	}

	public void setSignPassword(String signaturePassword) {
		this.signPassword = signaturePassword;
	}
	
	public boolean isDaemon() {
		return daemon;
	}

	public void setDaemon(boolean daemon) {
		this.daemon = daemon;
	}
}
