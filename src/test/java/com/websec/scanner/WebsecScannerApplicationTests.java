package com.websec.scanner;

import com.websec.scanner.cli.ScannerCLI;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class WebsecScannerApplicationTests {

	// ScannerCLI is a CommandLineRunner that launches the interactive menu and
	// blocks on System.in. Mocking it here stops that from firing during the
	// Spring context startup this test triggers.
	@MockitoBean
	private ScannerCLI scannerCLI;

	@Test
	void contextLoads() {
	}

}
