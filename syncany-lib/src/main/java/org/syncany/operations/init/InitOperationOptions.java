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

import java.util.List;

import org.syncany.config.to.RepoTO;
import org.syncany.crypto.CipherSpec;

public class InitOperationOptions extends AbstractInitOperationOptions {
	private boolean createTarget;
	private RepoTO repoTO;
	private boolean encryptionEnabled;
	private List<CipherSpec> cipherSpecs;
	private GenlinkOperationOptions genlinkOptions;

	public InitOperationOptions() {
		this.genlinkOptions = new GenlinkOperationOptions();
	}
	
	public boolean isCreateTarget() {
		return createTarget;
	}

	public void setCreateTarget(boolean createTarget) {
		this.createTarget = createTarget;
	}

	public RepoTO getRepoTO() {
		return repoTO;
	}

	public void setRepoTO(RepoTO repoTO) {
		this.repoTO = repoTO;
	}

	public boolean isEncryptionEnabled() {
		return encryptionEnabled;
	}

	public void setEncryptionEnabled(boolean encryptionEnabled) {
		this.encryptionEnabled = encryptionEnabled;
	}

	public List<CipherSpec> getCipherSpecs() {
		return cipherSpecs;
	}

	public void setCipherSpecs(List<CipherSpec> cipherSpecs) {
		this.cipherSpecs = cipherSpecs;
	}

	public GenlinkOperationOptions getGenlinkOptions() {
		return genlinkOptions;
	}

	public void setGenlinkOptions(GenlinkOperationOptions genlinkOptions) {
		this.genlinkOptions = genlinkOptions;
	}
}
