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
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.syncany.util.StringUtil;
import org.syncany.util.sign.ISigner;
import org.syncany.util.sign.IVerifier;
import org.syncany.util.sign.SignOutputStream;
import org.syncany.util.sign.VerifyInputStream;

/**
 * @author matmaul
 *
 */
public abstract class SignatureTransformer extends Transformer implements ISigner, IVerifier {
	public static final String PROPERTY_SIGN_KEY = "signkey";
	public static final String PROPERTY_VERIFY_KEY = "verifykey";
	private String digestAlgorithm;

	public SignatureTransformer(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public void init(Map<String, String> settings) throws Exception {
		String signKeyStr = settings.get(PROPERTY_SIGN_KEY);
		String verifyKeyStr = settings.get(PROPERTY_VERIFY_KEY);

		if (verifyKeyStr == null && signKeyStr == null) {
			throw new Exception("Setting '"+PROPERTY_VERIFY_KEY+"' or '"+PROPERTY_SIGN_KEY+"' must be filled.");
		}

		init(signKeyStr == null ? null : StringUtil.fromHex(signKeyStr), verifyKeyStr == null ? null : StringUtil.fromHex(verifyKeyStr));
	}

	protected abstract void init(byte[] signKey, byte[] verifyKey) throws Exception;
	protected abstract int getSignatureSize();

	@Override
	public OutputStream createOutputStream(OutputStream out) throws IOException {
		if (nextTransformer == null) {
			return createSignOutputStream(out);
		}
		else {
			return createSignOutputStream(nextTransformer.createOutputStream(out));
		}
	}

	public OutputStream createSignOutputStream(final OutputStream out) throws IOException {
		try {
			return new SignOutputStream(out, digestAlgorithm, this);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	@Override
	public InputStream createInputStream(final InputStream in) throws IOException {
		if (nextTransformer == null) {
			return createVerifyInputStream(in);
		}
		else {
			return createVerifyInputStream(nextTransformer.createInputStream(in));
		}
	}

	public InputStream createVerifyInputStream(final InputStream in) throws IOException {
		try {
			return new VerifyInputStream(in, digestAlgorithm, getSignatureSize(), this);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

}
