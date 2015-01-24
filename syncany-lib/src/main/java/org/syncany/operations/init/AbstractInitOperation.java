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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;

import org.syncany.config.Config;
import org.syncany.config.LocalEventBus;
import org.syncany.crypto.CipherUtil;
import org.syncany.crypto.MasterKey;
import org.syncany.operations.Operation;
import org.syncany.operations.daemon.messages.ShowMessageExternalEvent;
import org.syncany.plugins.UserInteractionListener;
import org.syncany.util.EnvironmentUtil;

/**
 * The abstract init operation implements common functions of the {@link InitOperation}
 * and the {@link ConnectOperation}. Its sole purpose is to avoid duplicate code in these
 * similar operations.
 *
 * @author Philipp C. Heckel <philipp.heckel@gmail.com>
 */
public abstract class AbstractInitOperation extends Operation {
	protected static final Logger logger = Logger.getLogger(AbstractInitOperation.class.getSimpleName());

	protected UserInteractionListener listener;
	protected LocalEventBus eventBus;
	protected AbstractInitOperationOptions options;

	public AbstractInitOperation(Config config, AbstractInitOperationOptions options, UserInteractionListener listener) {
		super(config);
		
		this.listener = listener;
		this.eventBus = LocalEventBus.getInstance();
		this.options = options;
	}

	protected File createAppDirs(File localDir) throws IOException {
		if (localDir == null) {
			throw new RuntimeException("Unable to create app dir, local dir is null.");
		}

		File appDir = new File(localDir, Config.DIR_APPLICATION);
		File logDir = new File(appDir, Config.DIR_LOG);
		File cacheDir = new File(appDir, Config.DIR_CACHE);
		File databaseDir = new File(appDir, Config.DIR_DATABASE);
		File stateDir = new File(appDir, Config.DIR_STATE);

		appDir.mkdir();
		logDir.mkdir();
		cacheDir.mkdir();
		databaseDir.mkdir();
		stateDir.mkdir();

		if (EnvironmentUtil.isWindows()) {
			Files.setAttribute(Paths.get(appDir.getAbsolutePath()), "dos:hidden", true);
		}

		return appDir;
	}

	protected void deleteAppDirs(File localDir) throws IOException {
		File appDir = new File(localDir, Config.DIR_APPLICATION);
		File logDir = new File(appDir, Config.DIR_LOG);
		File cacheDir = new File(appDir, Config.DIR_CACHE);
		File databaseDir = new File(appDir, Config.DIR_DATABASE);

		for (File log : logDir.listFiles()) {
			log.delete();
		}

		for (File cache : cacheDir.listFiles()) {
			cache.delete();
		}

		for (File db : databaseDir.listFiles()) {
			db.delete();
		}

		for (File file : appDir.listFiles()) {
			file.delete();
		}

		logDir.delete();
		cacheDir.delete();
		databaseDir.delete();
		appDir.delete();
	}

	protected void fireNotifyCreateMaster() {
		eventBus.post(new ShowMessageExternalEvent("Creating master key from password (this might take a while) ..."));
	}
	
	protected MasterKey getOrAskPasswords(boolean confirm, byte[] keySalt) throws Exception {
		if (options == null || options.getEncryptPassword() == null) {
			if (listener == null) {
				throw new Exception("Repository file is encrypted, but password cannot be queried (no listener).");
			}
			// TODO
//			private void askPasswords() {
//				encryptPassword = askPassword("Encrypt Password: ", false, false);
//				Boolean writeAccess = null;
//				while (writeAccess == null) {
//					char[] res = console.readPassword("Do you have write access on this repository ? (y/n)");
//					String resStr = new String(res);
//					if (resStr.toLowerCase().startsWith("y")) {
//						writeAccess = true;
//					}
//					if (resStr.toLowerCase().startsWith("n")) {
//						writeAccess = false;
//					}
//				}
//				if (writeAccess) {
//					signaturePassword = askPassword("Signature Password (can be empty): ", false, false);
//				
			String encryptPass = listener.onUserPassword("The password is used to encrypt data on the remote storage, choose wisely!", "Encrypt Password: ", confirm, false);
			String signPass = listener.onUserPassword("A different password can be used for write access, this can be left empty otherwise", "Sign Password: ", confirm, true);
			return createMasterKeyFromPasswords(encryptPass, signPass, keySalt);
		} else {
			return createMasterKeyFromPasswords(options.getEncryptPassword(), options.getSignPassword(), keySalt);
		}	
	}

	protected MasterKey createMasterKeyFromPasswords(String encryptPassword, String signPassword, byte[] salt) throws Exception {
		fireNotifyCreateMaster();

		return CipherUtil.createMasterKey(encryptPassword, signPassword, salt);
	}
	
}
