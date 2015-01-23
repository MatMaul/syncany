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
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.syncany.util.ThrowingInputStream;

/**
 * @author matmaul
 *
 */
public class VerifyInputStream extends ThrowingInputStream {

	protected byte[] buffer = null;
	protected int offset = 0;
	protected boolean endReached = false;
	protected MessageDigest digest;
	protected InputStream in;
	protected IVerifier verifier;
	protected int signatureSize;
	
	public VerifyInputStream(InputStream in, String digestAlgorithm, int signatureSize, IVerifier verifier) throws NoSuchAlgorithmException {
		this.in = in;
		this.digest = MessageDigest.getInstance(digestAlgorithm);
		this.signatureSize = signatureSize;
		this.verifier = verifier;
	}

	@Override
	public void close() throws IOException {
		in.close();
	}
	
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (endReached) {
			return -1;
		}
		initBuffer();
		
		byte[] tmpBuf = new byte[len];
		int res = in.read(tmpBuf);
		
		if (res == -1) {
			verifySignature();
			endReached = true;
			return -1;
		}

		if (res >= signatureSize) {
			System.arraycopy(buffer, offset, b, off, signatureSize - offset);
			System.arraycopy(buffer, 0, b, off + signatureSize - offset, offset);

			System.arraycopy(tmpBuf, 0, b, off + signatureSize, res - signatureSize);
			System.arraycopy(tmpBuf, res - signatureSize, buffer, 0, signatureSize);
			offset = 0;
		} else {
			/*
			 * The next block of code is the optimized version of :
			 * reorderBuffer();
			 * System.arraycopy(buffer, offset, b, off, signatureSize - offset);
			 * offset = res;
			 */
			if (res >= signatureSize - offset) {
				System.arraycopy(buffer, offset, b, off, signatureSize - offset);
				System.arraycopy(buffer, 0, b, off + signatureSize - offset, res - (signatureSize - offset));
				offset = res;
			} else {
				System.arraycopy(buffer, offset, b, off, res);
				offset = offset + res;
			}
			
			// TODO [low] Optimize that with arraycopy to avoid a call to reorderBuffer.
			// Might not even worse it since usually we should be EOF => computed in verifySignature anyway
			reorderBuffer();
			System.arraycopy(tmpBuf, 0, buffer, signatureSize - res, res);
			
		}
		digest.update(b, off, res);
		return res;
	}
	
	private void verifySignature() throws SignException {
		byte[] hash = digest.digest();
		reorderBuffer();
		if (!verifier.verifySignature(hash, buffer)) {
			throw new SignException("Signature verification failed.");
		}
	}
	
	private void initBuffer() throws IOException {
		if (buffer == null) {
			buffer = new byte[signatureSize];
			for (int i = 0 ; i < signatureSize ; i++) {
				int val = in.read();
				if (val == -1) {
					throw new SignException("Signature not present (file not long enough).");
				}
				buffer[i] = (byte)val;
			}
		}
	}

	@Override
	public int read() throws IOException {
		if (endReached) {
			return -1;
		}
		initBuffer();
		int new_ = in.read();
		if (new_ == -1) {
			verifySignature();
			endReached = true;
			return -1;
		}
		byte val = (byte)buffer[offset];

		buffer[offset] = (byte)new_;
		offset = (offset + 1) % signatureSize;

		digest.update(val);
		return val & 0xFF;
	}
	
	private void reorderBuffer() {
		if (offset != 0) {
			byte[] reorderedBuf = new byte[signatureSize];
			for (int i = 0 ; i < offset ; i++) {
				reorderedBuf[signatureSize + i - offset] = buffer[i];
			}
			for (int i = offset ; i < signatureSize ; i++) {
				reorderedBuf[i - offset] = buffer[i];
			}
			buffer = reorderedBuf;
			offset = 0;
		}
	}

}
