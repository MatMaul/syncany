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

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.i2p.crypto.eddsa.EdDSAEngine;

import org.syncany.crypto.CipherUtil;

/**
 * @author matmaul
 *
 */
public class Ed25519SignTransformer extends SignatureTransformer {
	public static final String TYPE = "ed25519-sign";

	private PrivateKey signKey;
	private PublicKey verifyKey;

	public Ed25519SignTransformer() {
		super("SHA1");
	}

	public Ed25519SignTransformer(PublicKey verifyKey, PrivateKey signKey) throws InvalidKeyException {
		super("SHA1");
		this.verifyKey = verifyKey;
		this.signKey = signKey;
	}

	@Override
	protected void init(byte[] signKey, byte[] verifyKey) throws Exception {

		if (signKey != null) {
			this.signKey = CipherUtil.createSignKey(signKey);
		}
		if (verifyKey != null) {
			this.verifyKey = CipherUtil.createVerifyKey(verifyKey);
		} else if (signKey != null) {
			this.verifyKey = CipherUtil.createVerifyKey(CipherUtil.createSignKey(signKey));
		} else {
			throw new Exception("no sign key nor verify key provided");
		}
	}

	@Override
	public boolean verifySignature(byte[] msg, byte[] signature) {
		try {
			if (verifyKey == null) {
				return true;
			}
			EdDSAEngine e = new EdDSAEngine();
			e.initVerify(verifyKey);
			e.update(msg);
			return e.verify(signature);
		} catch(Exception ee) {
			return false;
		}
	}

	@Override
	public byte[] generateSignature(byte[] msg) {
		if (signKey == null) {
			throw new RuntimeException("No sign key available");
		}
		try {
			EdDSAEngine e = new EdDSAEngine();
			e.initSign(signKey);
			e.update(msg);
			return e.sign();
		}
		catch (Exception ee) {
			throw new RuntimeException(ee);
		}
	}

	@Override
	protected int getSignatureSize() {
		return 64;
	}

	@Override
	public String toString() {
		return (nextTransformer == null) ? "Ed25519Sign" : "Ed25519Sign-"+nextTransformer;
	}
}
