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
package org.syncany.chunk;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.syncany.crypto.CipherSession;
import org.syncany.crypto.CipherSpec;
import org.syncany.crypto.CipherSpecs;
import org.syncany.crypto.MasterKey;
import org.syncany.crypto.MultiCipherInputStream;
import org.syncany.crypto.MultiCipherOutputStream;
import org.syncany.util.StringUtil;

/**
 * The CipherTransformer can be used to encrypt/decrypt files (typically 
 * {@link MultiChunk}s) using the {@link MultiCipherOutputStream} and
 * {@link MultiCipherInputStream}. 
 * 
 * A CipherTransformer requires a list of {@link CipherSpec}s and the master 
 * key. It can be instantiated using a property list (from a config file) or
 * by passing the dependencies to the constructor.
 * 
 * @author Philipp C. Heckel <philipp.heckel@gmail.com>
 */
public class CipherTransformer extends Transformer {
	public static final String TYPE = "cipher";
	public static final String PROPERTY_CIPHER_SPECS = "cipherspecs";
	public static final String PROPERTY_KEY_SALT = "salt";
	public static final String PROPERTY_ENCRYPT_KEY = "encryptkey";
	
	private List<CipherSpec> cipherSpecs;
	private CipherSession cipherSession;
	
	public CipherTransformer() {
		this.cipherSpecs = new ArrayList<CipherSpec>();
		this.cipherSession = null;
	}
	
    public CipherTransformer(List<CipherSpec> cipherSpecs, MasterKey masterKey) {
    	this.cipherSpecs = cipherSpecs;
    	this.cipherSession = new CipherSession(masterKey);
    }    
    
    /**
     * Initializes the cipher transformer using a settings map. Required settings
     * are: {@link #PROPERTY_CIPHER_SPECS}, {@link #PROPERTY_MASTER_KEY} and 
     * {@link #PROPERTY_MASTER_KEY_SALT}.
     */
    @Override
    public void init(Map<String, String> settings) throws Exception {
    	String encryptKeyStr = settings.get(PROPERTY_ENCRYPT_KEY);
    	String keySaltStr = settings.get(PROPERTY_KEY_SALT);
    	String cipherSpecsListStr = settings.get(PROPERTY_CIPHER_SPECS);
    	
    	if (encryptKeyStr == null || keySaltStr == null || cipherSpecsListStr == null) {
    		throw new Exception("Settings '"+PROPERTY_CIPHER_SPECS+"', '"+PROPERTY_ENCRYPT_KEY+"' and '"+PROPERTY_KEY_SALT+"' must be filled.");
    	}
    	
    	initCipherSpecs(cipherSpecsListStr);
    	initCipherSession(encryptKeyStr, keySaltStr);    	
    }
    
    private void initCipherSpecs(String cipherSpecListStr) throws Exception {
    	String[] cipherSpecIdStrs = cipherSpecListStr.split(",");
    	
    	for (String cipherSpecIdStr : cipherSpecIdStrs) {
    		int cipherSpecId = Integer.parseInt(cipherSpecIdStr);
    		CipherSpec cipherSpec = CipherSpecs.getCipherSpec(cipherSpecId);
    		
    		if (cipherSpec == null) {
    			throw new Exception("Cannot find cipher suite with ID '"+cipherSpecId+"'");
    		}
    		
    		cipherSpecs.add(cipherSpec);
    	}
	}

	private void initCipherSession(String encryptKeyStr, String keySaltStr) {
		byte[] masterKeySalt = StringUtil.fromHex(keySaltStr);
		byte[] masterEncryptBytes = StringUtil.fromHex(encryptKeyStr);
		
		MasterKey masterKey = new MasterKey(new SecretKeySpec(masterEncryptBytes, "RAW"), masterKeySalt, null);		
		cipherSession = new CipherSession(masterKey);
	}

	@Override
	public OutputStream createOutputStream(OutputStream out) throws IOException {
		if (cipherSession == null) {
			throw new RuntimeException("Cipher session is not initialized. Call init() before!");
		}

        if (nextTransformer == null) {
            return new MultiCipherOutputStream(out, cipherSpecs, cipherSession);
        }
        else {
            return new MultiCipherOutputStream(nextTransformer.createOutputStream(out), cipherSpecs, cipherSession);
        }
    }

    @Override
    public InputStream createInputStream(InputStream in) throws IOException {
		if (cipherSession == null) {
			throw new RuntimeException("Cipher session is not initialized. Call init() before!");
		}
		
        if (nextTransformer == null) {
            return new MultiCipherInputStream(in, cipherSession);
        }
        else {
            return new MultiCipherInputStream(nextTransformer.createInputStream(in), cipherSession);
        }
    }    

    @Override
    public String toString() {
        return (nextTransformer == null) ? "Cipher" : "Cipher-"+nextTransformer;
    }     
}
