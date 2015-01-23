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
package org.syncany.util.sign;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author matmaul
 *
 */
public class SignOutputStream extends OutputStream {
	
	protected OutputStream out;
	protected String digestAlgorithm;
	protected MessageDigest digest;
	protected ISigner signer;

	public SignOutputStream(OutputStream out, String digestAlgorithm, ISigner signer) throws NoSuchAlgorithmException {
		this.out = out;
		this.digest = MessageDigest.getInstance(digestAlgorithm);
		this.signer = signer;
	}

	@Override
	public void write(int b) throws IOException {
		digest.update((byte)b);
		out.write(b);
	}
	
	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		digest.update(b, off, len);
		out.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		byte[] hash = digest.digest();
		byte[] signature = signer.generateSignature(hash);
		out.write(signature);
		out.close();
	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}

}
