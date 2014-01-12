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

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.syncany.chunk.Ed25519SignTransformer;
import org.syncany.config.Config;
import org.syncany.config.to.ConfigTO;
import org.syncany.config.to.MasterTO;
import org.syncany.config.to.RepoTO;
import org.syncany.connection.plugins.MasterRemoteFile;
import org.syncany.connection.plugins.RepoRemoteFile;
import org.syncany.connection.plugins.StorageException;
import org.syncany.connection.plugins.TransferManager;
import org.syncany.crypto.CipherSpec;
import org.syncany.crypto.CipherUtil;
import org.syncany.crypto.MasterKey;
import org.syncany.operations.GenlinkOperation.GenlinkOperationResult;

/**
 * The init operation initializes a new repository at a given remote storage
 * location. Its responsibilities include:
 * 
 * <ul>
 *   <li>Generating a master key from the user password (if encryption is enabled)
 *       using the {@link CipherUtil#createMasterKey(String) createMasterKey()} method</li>
 *   <li>Creating the local Syncany folder structure in the local directory (.syncany 
 *       folder and the sub-structure).</li>
 *   <li>Initializing the remote storage (creating folder-structure, if necessary)
 *       using the transfer manager's {@link TransferManager#init()} method.</li>
 *   <li>Creating a new repo and master file using {@link RepoTO} and {@link MasterTO},
 *       saving them locally and uploading them to the remote repository.</li>
 * </ul> 
 *   
 * @author Philipp C. Heckel <philipp.heckel@gmail.com>
 */
public class InitOperation extends AbstractInitOperation {
    private static final Logger logger = Logger.getLogger(InitOperation.class.getSimpleName());        
    private InitOperationOptions options;
    private TransferManager transferManager;
    
    public InitOperation(InitOperationOptions options, InitOperationListener listener) {
        super(null, options, listener);
        this.options = options;
    }        
            
    @Override
    public InitOperationResult execute() throws Exception {
		logger.log(Level.INFO, "");
		logger.log(Level.INFO, "Running 'Init'");
		logger.log(Level.INFO, "--------------------------------------------");                      

		transferManager = createTransferManager(options.getConfigTO().getConnectionTO());
		
		if (repoFileExistsOnRemoteStorage(transferManager)) {
			throw new Exception("Repo already exists. Use 'connect' command to connect to existing repository."); 
		}
		logger.log(Level.INFO, "Creating local repository");
		// Create local .syncany directory
		File appDir = createAppDirs(options.getLocalDir());	
		File configFile = new File(appDir+"/"+Config.FILE_CONFIG);
		File repoFile = new File(appDir+"/"+Config.FILE_REPO);
		File masterFile = new File(appDir+"/"+Config.FILE_MASTER);
		
		// Save config.xml and repo file		
		if (options.isEncryptionEnabled()) {
			MasterKey masterKey = createMasterKeyFromPasswords(options.getEncryptPassword(), options.getSignaturePassword(), null); // This takes looong!			
			
			options.getConfigTO().setMasterKey(masterKey);
			// TODO [low] ugly, hardcoded dependency to a transformer
			byte[] verifyKey = Ed25519SignTransformer.generateVerifyKey(masterKey.getSigningKey().getEncoded());
			options.getRepoTO().setVerifyKey(verifyKey);
			
			writeXmlFile(new MasterTO(masterKey.getSalt()), masterFile);
			writeEncryptedXmlFile(options.getRepoTO(), repoFile, options.getCipherSpecs(), masterKey);				
		}	
		else {
			writeXmlFile(options.getRepoTO(), repoFile);
		}	
		
		writeXmlFile(options.getConfigTO(), configFile);

		logger.log(Level.INFO, "Uploading local repository");
		
		// Make remote changes
		try {
			transferManager.init();
		}
		catch (StorageException e) {
			//Storing remotely failed. Remove all the directories and files we just created
			try {
				deleteAppDirs(options.getLocalDir());
			}
			catch (Exception e1) {
				throw new Exception("StorageException for remote. Cleanup failed. There may be local directories left");
			}
			throw new Exception("StorageException for remote. Cleaned local repository.");
 		}
		
		if (masterFile.exists()) {
			uploadMasterFile(masterFile, transferManager);
		}
		
		uploadRepoFile(repoFile, transferManager);
		
		// Make link		
		GenlinkOperationResult genlinkOperationResult = generateLink(options.getConfigTO());
					
		return new InitOperationResult(genlinkOperationResult);
    }          
    
	private GenlinkOperationResult generateLink(ConfigTO configTO) throws Exception {
		return new GenlinkOperation(options.getConfigTO()).execute();
	}

	protected boolean repoFileExistsOnRemoteStorage(TransferManager transferManager) throws Exception {
		try {
			Map<String, RepoRemoteFile> repoFileList = transferManager.list(RepoRemoteFile.class);			
			return repoFileList.size() > 0;
		}
		catch (Exception e) {
			throw new Exception("Unable to connect to repository.", e);
		}		
	}
	
	private void uploadMasterFile(File masterFile, TransferManager transferManager) throws Exception {    		
		transferManager.upload(masterFile, new MasterRemoteFile());
	}  
	
	private void uploadRepoFile(File repoFile, TransferManager transferManager) throws Exception {    		
		transferManager.upload(repoFile, new RepoRemoteFile());
	}    	
	
    public static class InitOperationOptions extends AbstractInitOperationOptions {

    	private RepoTO repoTO;
    	private boolean encryptionEnabled;
    	private List<CipherSpec> cipherSpecs;
    	
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
    }
    
    public class InitOperationResult implements OperationResult {
        private GenlinkOperationResult genLinkResult;

		public InitOperationResult(GenlinkOperationResult genLinkResult) {
			this.genLinkResult = genLinkResult;
		}

		public GenlinkOperationResult getGenLinkResult() {
			return genLinkResult;
		}              
    }
}