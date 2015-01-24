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
package org.syncany.operations.daemon.messages;

import org.simpleframework.xml.Element;
import org.syncany.operations.daemon.messages.api.ExternalEvent;

public class GetPasswordUserInteractionExternalEvent extends ExternalEvent {
	@Element(name = "header", required = true)
	private String header;
	
	@Element(name = "message", required = true)
	private String message;
	
	private boolean allowEmpty = false;

	private boolean confirm = true;
	
	public GetPasswordUserInteractionExternalEvent() {
		// Nothing
	}
	
	public GetPasswordUserInteractionExternalEvent(String header, String message, boolean confirm, boolean allowEmpty) {
		this.header = header;
		this.message = message;
		this.confirm  = confirm;
		this.allowEmpty = allowEmpty;
	}
	
	public String getHeader() {
		return header;
	}

	public String getMessage() {
		return message;
	}
	
	public boolean allowEmpty() {
		return allowEmpty;
	}
	
	public boolean confirm() {
		return confirm;
	}
}
