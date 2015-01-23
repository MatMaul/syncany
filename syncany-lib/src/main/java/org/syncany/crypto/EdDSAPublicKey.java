package org.syncany.crypto;

import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class EdDSAPublicKey extends net.i2p.crypto.eddsa.EdDSAPublicKey {
	private static final long serialVersionUID = 7038854674392737731L;

	public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
		super(spec);
	}
	
	@Override
	public byte[] getEncoded() {
		return getAbyte();
	}

}
