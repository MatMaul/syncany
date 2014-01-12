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

import org.abstractj.kalium.keys.SigningKey;
import org.abstractj.kalium.keys.VerifyKey;

/**
 * @author matmaul
 *
 */
public class Ed25519SignTransformer extends SignatureTransformer {
	public static final String TYPE = "ed25519-sign";

	private SigningKey signingKey;
	private VerifyKey verifyKey;
	
	public Ed25519SignTransformer() {
		this(null, null);
	}

	public Ed25519SignTransformer(VerifyKey verifyKey, SigningKey signingKey) {
		super("SHA1");
		this.verifyKey = verifyKey;
		this.signingKey = signingKey;
	}

	@Override
	protected void init(byte[] signingKey, byte[] verifyKey) {

		if (signingKey != null) {
			this.signingKey = new SigningKey(signingKey);
		}
		if (verifyKey != null) {
			this.verifyKey = new VerifyKey(verifyKey);
		} else if (this.signingKey != null) {
			this.verifyKey = this.signingKey.getVerifyKey();
		} else {
			throw new RuntimeException("no signing key nor verify key provided");
		}

	} 

	@Override
	public boolean verifySignature(byte[] msg, byte[] signature) {
		try {
			if (verifyKey == null) {
				return true;
			}
			return verifyKey.verify(msg, signature);
		} catch(RuntimeException e) {
			return false;
		}
	}

	@Override
	public byte[] generateSignature(byte[] msg) {
		if (signingKey == null) {
			throw new RuntimeException("No signing key available");
		}
		return signingKey.sign(msg);
	}

	@Override
	protected int getSignatureSize() {
		return 64;
	}

	@Override
	public String toString() {
		return (nextTransformer == null) ? "Ed25519Sign" : "Ed25519Sign-"+nextTransformer;
	}

	public static byte[] generateVerifyKey(byte[] signingKey) {
		return new SigningKey(signingKey).getVerifyKey().toBytes();
	}

}
