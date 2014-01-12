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
package org.syncany.crypto;

import javax.crypto.SecretKey;

import org.abstractj.kalium.keys.SigningKey;

/**
 * @author matmaul
 *
 */
public class MasterKey {
	protected SecretKey encryptKey;
	protected SecretKey signingKey;
	protected SigningKey kaliumSigningKey;
	protected byte[] salt;
	
	public MasterKey(SecretKey encryptKey, byte[] salt) {
		this(encryptKey, salt, null);
		
	}
	
	public MasterKey(SecretKey encryptKey, byte[] salt, SecretKey signingKey) {
		this.encryptKey = encryptKey;
		this.salt = salt;
		this.signingKey = signingKey;
		if (signingKey != null) {
			kaliumSigningKey = new SigningKey(signingKey.getEncoded());
		}

	}
	
	public byte[] calculateVerifyKeyBytes() {
		return kaliumSigningKey.getVerifyKey().toBytes();
	}
	
	public byte[] sign(byte[] message) {
		return kaliumSigningKey.sign(message);
	}
	
	public byte[] getSalt() {
		return salt;
	}
	
	/**
	 * can be null (no write access)
	 */
	public SecretKey getSigningKey() {
		return signingKey;
	}
	
	/**
	 * cannot be null
	 */
	public SecretKey getEncryptKey() {
		return encryptKey;
	}

}
