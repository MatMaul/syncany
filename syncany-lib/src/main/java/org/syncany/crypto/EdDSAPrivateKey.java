package org.syncany.crypto;

import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

public class EdDSAPrivateKey extends net.i2p.crypto.eddsa.EdDSAPrivateKey {
	private static final long serialVersionUID = -5749014958652482747L;

	public EdDSAPrivateKey(EdDSAPrivateKeySpec spec) {
    	super(spec);
    }

    public byte[] getEncoded() {
        return getSeed();
    }
}
