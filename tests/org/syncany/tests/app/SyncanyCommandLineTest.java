package org.syncany.tests.app;

import static org.junit.Assert.*;

import java.io.File;
import java.util.Map;

import org.junit.Test;
import org.syncany.Syncany;
import org.syncany.tests.util.TestConfigUtil;

public class SyncanyCommandLineTest {	
	@Test
	public void testSyncanyCliSyncUpWithNoCleanup() throws Exception {
		Map<String, String> connectionSettings = TestConfigUtil.createTestLocalConnectionSettings();
		Map<String, String> clientA = TestConfigUtil.createTestLocalConfigFile("A", connectionSettings);

		for (int i=1; i<=20; i++) {
			new File(clientA.get("localDir")+"/somefolder"+i).mkdir();
		
			new Syncany(new String[] { 
					"--config", clientA.get("configFile"), "up", "--no-cleanup" }).start();
		}
		
		for (int i=1; i<=20; i++) {
			File databaseFileInRepo = new File(connectionSettings.get("path")+"/db-A-"+i);			
			assertTrue("Database file SHOULD exist: "+databaseFileInRepo, databaseFileInRepo.exists());
		}
				
		TestConfigUtil.deleteTestLocalConfigAndData(clientA);		
	}	
	
	@Test
	public void testSyncanyCliWithLogLevelOff() throws Exception {
		Map<String, String> connectionSettings = TestConfigUtil.createTestLocalConnectionSettings();
		Map<String, String> clientA = TestConfigUtil.createTestLocalConfigFile("A", connectionSettings);

		new File(clientA.get("localDir")+"/somefolder1").mkdir();
		new File(clientA.get("localDir")+"/somefolder2").mkdir();
				
		new Syncany(new String[] { 
				"--loglevel", "OFF", 
				"--config", clientA.get("configFile"), "status" }).start();
		
		fail("Somehow catch the output");
		TestConfigUtil.deleteTestLocalConfigAndData(clientA);		
	}	
	
	@Test
	public void testSyncanyCliWithLogFile() throws Exception {
		Map<String, String> connectionSettings = TestConfigUtil.createTestLocalConnectionSettings();
		Map<String, String> clientA = TestConfigUtil.createTestLocalConfigFile("A", connectionSettings);

		File tempLogFile = new File(clientA.get("appDir")+"/log");
		
		new File(clientA.get("localDir")+"/somefolder1").mkdir();
		new File(clientA.get("localDir")+"/somefolder2").mkdir();
				
		new Syncany(new String[] { 
				"--log", tempLogFile.getAbsolutePath(), 
				"--config", clientA.get("configFile"), "status" }).start();
		
		assertTrue("Log file should exist.", tempLogFile.exists());
		
		TestConfigUtil.deleteTestLocalConfigAndData(clientA);		
	}		
}