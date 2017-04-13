package pt.ulisboa.tecnico.sec.tg11;

import org.junit.After;
import org.junit.Before;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;

import java.io.FileInputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public abstract class AbstractTest {
		private static final String PATH_TO_SERVER_CERT = "./src/main/resources/server1.cer";
		private static final String PATH_TO_FAKE_CERT = "./src/main/resources/server2.cer";
		PWMInterface _serverRemote;
		KeyPair keypair;
		Server serverObject;
		PublicKey _serverPublicKey;
		PublicKey _fakePublicKey;
		
	@Before
	public void setUp() throws Exception {
		serverObject = new Server(1);
		serverObject.setUp();


		FileInputStream fin = new FileInputStream(PATH_TO_SERVER_CERT);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		
		fin = new FileInputStream(PATH_TO_FAKE_CERT);
		f = CertificateFactory.getInstance("X.509");
		X509Certificate fakeCert = (X509Certificate)f.generateCertificate(fin);

		_serverPublicKey = certificate.getPublicKey();
		_fakePublicKey = fakeCert.getPublicKey();
		

		String text = "RMI Test Message";

		try {
			Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
			_serverRemote = (PWMInterface) registry.lookup("PWMServer1");
		} catch (Exception e) {
			e.printStackTrace();
		}


		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		keypair = keyPairGenerator.genKeyPair();

	}

	@After
	public void tearDown() throws Exception {
		serverObject.shutdown();
	}
}
