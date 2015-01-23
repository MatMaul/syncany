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
package org.syncany.crypto;

import java.security.PrivateKey;

import javax.crypto.spec.SecretKeySpec;

import org.simpleframework.xml.convert.Converter;
import org.simpleframework.xml.stream.InputNode;
import org.simpleframework.xml.stream.OutputNode;
import org.syncany.util.StringUtil;

/**
 * Converter to properly encode a {@link MasterKey} when writing 
 * an XML. Salt and key are serialized as attributes.
 * 
 * @author Christian Roth <christian.roth@port17.de>
 */
public class MasterKeyConverter implements Converter<MasterKey> {

	public MasterKey read(InputNode node) throws Exception {
		byte[] saltBytes = StringUtil.fromHex(node.getAttribute("salt").getValue());
		byte[] encryptKeyBytes = StringUtil.fromHex(node.getAttribute("encryptkey").getValue());
		byte[] signKeyBytes = StringUtil.fromHex(node.getAttribute("signkey").getValue());

		PrivateKey signKey = null;
		if (signKeyBytes != null && !(signKeyBytes.length == 0)) {
			signKey = CipherUtil.createSignKey(signKeyBytes);
		}

		return new MasterKey(new SecretKeySpec(encryptKeyBytes, CipherParams.MASTER_KEY_DERIVATION_FUNCTION), saltBytes, signKey);
	}

	public void write(OutputNode node, MasterKey masterKey) {
		node.setAttribute("salt", StringUtil.toHex(masterKey.getSalt()));
		node.setAttribute("encryptkey", StringUtil.toHex(masterKey.getEncryptKey().getEncoded()));
		if (masterKey.getSignKey() != null) {
			node.setAttribute("signkey", StringUtil.toHex(masterKey.getSignKey().getEncoded()));
		}
	}
}