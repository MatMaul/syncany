/*
 * Syncany, www.syncany.org
 * Copyright (C) 2011-2013 Philipp C. Heckel <philipp.heckel@gmail.com> 
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
package org.syncany.operations;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.simpleframework.xml.Serializer;
import org.simpleframework.xml.core.Persister;
import org.syncany.config.Config;
import org.syncany.config.to.ConfigTO;
import org.syncany.config.to.ConfigTO.ConnectionTO;
import org.syncany.config.to.RepoTO;
import org.syncany.connection.plugins.Connection;
import org.syncany.connection.plugins.Plugin;
import org.syncany.connection.plugins.Plugins;
import org.syncany.connection.plugins.StorageException;
import org.syncany.connection.plugins.TransferManager;
import org.syncany.crypto.CipherSpec;
import org.syncany.crypto.CipherUtil;
import org.syncany.crypto.MasterKey;
import org.syncany.util.FileUtil;

/**
 * The abstract init operation implements common functions of the {@link InitOperation}
 * and the {@link ConnectOperation}. Its sole purpose is to avoid duplicate code in these
 * similar operations.
 *   
 * @author Philipp C. Heckel <philipp.heckel@gmail.com>
 */
public abstract class AbstractInitOperation extends Operation {
	protected InitOperationListener listener;
	protected AbstractInitOperationOptions options;

	public AbstractInitOperation(Config config) {
		this(config, null, null);
	}
	
	public AbstractInitOperation(Config config, AbstractInitOperationOptions options, InitOperationListener listener) {
		super(config);
		this.listener = listener;
		this.options = options;
	}	

	protected TransferManager createTransferManager(ConnectionTO connectionTO) throws StorageException {
		Plugin plugin = Plugins.get(connectionTO.getType());

		Connection connection = plugin.createConnection();
		connection.init(connectionTO.getSettings());

		return connection.createTransferManager();
	}

	protected File createAppDirs(File localDir) throws Exception {
		if (localDir == null) {
			throw new Exception("Unable to create app dir, local dir is null.");
		}

		File appDir = new File(localDir+"/"+Config.DIR_APPLICATION);
		File logDir = new File(appDir+"/"+Config.DIR_LOG);
		File cacheDir = new File(appDir+"/"+Config.DIR_CACHE);
		File databaseDir = new File(appDir+"/"+Config.DIR_DATABASE);

		appDir.mkdir();
		logDir.mkdir();
		cacheDir.mkdir();
		databaseDir.mkdir();

		if (FileUtil.isWindows()) {
			Files.setAttribute(Paths.get(appDir.getAbsolutePath()), "dos:hidden", true);
		}

		return appDir;
	}

	protected void deleteAppDirs(File localDir) throws Exception {
		File appDir = new File(localDir+"/"+Config.DIR_APPLICATION);
		File logDir = new File(appDir+"/"+Config.DIR_LOG);
		File cacheDir = new File(appDir+"/"+Config.DIR_CACHE);
		File databaseDir = new File(appDir+"/"+Config.DIR_DATABASE);
		for (File log : logDir.listFiles()) {
			log.delete();
		}
		logDir.delete();
		for (File cache : cacheDir.listFiles()) {
			cache.delete();
		}
		cacheDir.delete();
		for (File db : databaseDir.listFiles()) {
			db.delete();
		}
		databaseDir.delete();
		for (File file : appDir.listFiles()) {
			file.delete();
		}
		appDir.delete();

	}

	protected void writeXmlFile(Object source, File file) throws Exception {
		Serializer serializer = new Persister();
		serializer.write(source, file);	
	}	

	protected void writeEncryptedXmlFile(RepoTO repoTO, File file, List<CipherSpec> cipherSuites, MasterKey masterKey) throws Exception {				
		ByteArrayOutputStream plaintextRepoOutputStream = new ByteArrayOutputStream();
		Serializer serializer = new Persister();
		serializer.write(repoTO, plaintextRepoOutputStream);

		CipherUtil.encrypt(new ByteArrayInputStream(plaintextRepoOutputStream.toByteArray()), new FileOutputStream(file), cipherSuites, masterKey);
	}	

	protected String getEncryptedLink(ConnectionTO connectionTO, List<CipherSpec> cipherSuites, MasterKey encryptKey) throws Exception {
		ByteArrayOutputStream plaintextOutputStream = new ByteArrayOutputStream();
		Serializer serializer = new Persister();
		serializer.write(connectionTO, plaintextOutputStream);

		byte[] encryptKeySalt = encryptKey.getSalt();
		String encryptKeySaltEncodedStr = new String(Base64.encodeBase64(encryptKeySalt, false));

		byte[] encryptedConnectionBytes = CipherUtil.encrypt(new ByteArrayInputStream(plaintextOutputStream.toByteArray()), cipherSuites, encryptKey);
		String encryptedEncodedStorageXml = new String(Base64.encodeBase64(encryptedConnectionBytes, false));

		return "syncany://storage/1/"+encryptKeySaltEncodedStr+"-"+encryptedEncodedStorageXml;				
	}

	protected String getPlaintextLink(ConnectionTO connectionTO) throws Exception {
		ByteArrayOutputStream plaintextOutputStream = new ByteArrayOutputStream();
		Serializer serializer = new Persister();
		serializer.write(connectionTO, plaintextOutputStream);

		byte[] plaintextStorageXml = plaintextOutputStream.toByteArray();
		String plaintextEncodedStorageXml = new String(Base64.encodeBase64(plaintextStorageXml, false));

		return "syncany://storage/1/not-encrypted/"+plaintextEncodedStorageXml;			
	}

	protected MasterKey getOrAskPasswordRepoFile(byte[] keySalt) throws Exception {
		if (options == null || options.getEncryptPassword() == null) {
			if (listener == null) {
				throw new Exception("Repository file is encrypted, but password cannot be queried (no listener).");
			}

			String encryptPass = listener.getEncryptPasswordCallback();
			String signPass = listener.getSignaturePasswordCallback();
			return createMasterKeyFromPasswords(encryptPass, signPass, keySalt);
		} else {
			return createMasterKeyFromPasswords(options.getEncryptPassword(), options.getSignaturePassword(), keySalt);
		}	
	}

	protected MasterKey createMasterKeyFromPasswords(String encryptPassword, String signaturePassword, byte[] salt) throws Exception {
		if (listener != null) {
			listener.notifyGenerateMasterKey();
		}

		return CipherUtil.createMasterKey(encryptPassword, signaturePassword, salt);
	}

	public static interface InitOperationListener {
		public String getEncryptPasswordCallback();
		public String getSignaturePasswordCallback();
		public void notifyGenerateMasterKey();
	}

	public static class AbstractInitOperationOptions implements OperationOptions {
		private File localDir;
		private ConfigTO configTO;
		private String encryptPassword;
		private String signaturePassword;

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

		public String getSignaturePassword() {
			return signaturePassword;
		}

		public void setSignaturePassword(String signaturePassword) {
			this.signaturePassword = signaturePassword;
		}
	}
}
