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

import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * @author matmaul
 *
 */
public class MasterKey {
	private SecretKey encryptKey;
	private PrivateKey signKey;
	private byte[] salt;
	
	public MasterKey(SecretKey encryptKey, byte[] salt) {
		this(encryptKey, salt, null);
		
	}
	
	public MasterKey(SecretKey encryptKey, byte[] salt, PrivateKey signKey) {
		this.encryptKey = encryptKey;
		this.salt = salt;
		this.signKey = signKey;

	}
	
	public byte[] getSalt() {
		return salt;
	}
	
	/**
	 * can be null (no write access)
	 */
	public PrivateKey getSignKey() {
		return signKey;
	}
	
	/**
	 * cannot be null
	 */
	public SecretKey getEncryptKey() {
		return encryptKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(salt);
		result = prime * result + ((encryptKey == null) ? 0 : encryptKey.hashCode());
		result = prime * result + ((signKey == null) ? 0 : signKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		MasterKey other = (MasterKey) obj;
		if (!Arrays.equals(salt, other.salt))
			return false;
		if (encryptKey == null) {
			if (other.encryptKey != null)
				return false;
		} else if (!encryptKey.equals(other.encryptKey))
			return false;
		// TODO implements equals in EdDSA*Key
//		if (signKey == null) {
//			if (other.signKey != null)
//				return false;
//		} else if (!signKey.equals(other.signKey))
//			return false;
		return true;
	}	
}
