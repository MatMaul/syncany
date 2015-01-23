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
package org.syncany.tests.scenarios;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;
import org.syncany.operations.down.DownOperationResult;
import org.syncany.plugins.transfer.TransferSettings;
import org.syncany.tests.util.TestClient;
import org.syncany.tests.util.TestConfigUtil;

/**
 * @author matmaul
 *
 */
public class SignatureScenarioTest {
	private static TestClient clientA;
	private static TestClient clientB;
	private static TestClient unauthorizedClientC;

	@BeforeClass
	public static void before() throws Exception {
		// Setup 
		TransferSettings testConnection = TestConfigUtil.createTestLocalConnection();

		clientA = new TestClient("A", testConnection);
		clientB = new TestClient("B", testConnection);
		unauthorizedClientC = new TestClient("C", testConnection, true);
	}

	@Test
	public void testSignature() throws Exception {
		if (TestConfigUtil.getCrypto()) {
			// Run 
			clientA.createNewFile("A-file1.jpg", 10000);
			clientA.up();

			DownOperationResult res = clientB.down();
			assertTrue("Client B: A-file1.jpg not synchronized", res.getChangeSet().getNewFiles().contains("A-file1.jpg"));
			clientB.createNewFile("B-file1.jpg", 10000);
			clientB.up();

			res = unauthorizedClientC.down();
			assertTrue("Client C: A-file1.jpg not synchronized", res.getChangeSet().getNewFiles().contains("A-file1.jpg"));
			assertTrue("Client C: B-file1.jpg not synchronized", res.getChangeSet().getNewFiles().contains("B-file1.jpg"));

			unauthorizedClientC.createNewFile("C-file1.jpg", 10000);
			unauthorizedClientC.up();

			res = clientB.down();
			assertFalse("Client B: C-file1.jpg of unauthorized client synchronized", res.getChangeSet().getNewFiles().contains("C-file1.jpg"));

			clientB.createNewFile("B-file2.jpg", 1000);
			clientB.up();

			res = clientA.down();
			assertFalse("Client A: C-file1.jpg of unauthorized client synchronized", res.getChangeSet().getNewFiles().contains("C-file1.jpg"));
			assertTrue("Client A: B-file1.jpg not synchronized", res.getChangeSet().getNewFiles().contains("B-file1.jpg"));
			assertTrue("Client A: B-file2.jpg not synchronized", res.getChangeSet().getNewFiles().contains("B-file2.jpg"));

			clientA.cleanup();
			clientB.cleanup();
			unauthorizedClientC.cleanup();
		}
	}
}
