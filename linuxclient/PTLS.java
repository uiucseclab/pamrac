package edu.illinois.cs.salmon.fredshoppinglist;

import java.io.*;
import javax.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;

public class PTLS
{
	//public SSLSocket skt;
	//public SSLSession s;
	
	public static SSLSocket connectTLS(String serverAddr, byte[] serverCert) throws Exception
	{
		String serverHost;
		int serverPort;
		if(serverAddr.indexOf(":") >= 0)
		{
			serverHost = serverAddr.substring(0, serverAddr.indexOf(":"));
			String serverPortStr = serverAddr.substring(serverAddr.indexOf(":")+1);
			serverPort = Integer.parseInt(serverPortStr);
		}
		else
		{
			serverPort = 443;
			serverHost = serverAddr;
		}

		// Create an SSLContext that uses our TrustManager (if applicable)
		SSLContext context = SSLContext.getInstance("TLS");
		
		if(serverCert != null)
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			// From https://www.washington.edu/itconnect/security/ca/load-der.crt
			InputStream caInput = new ByteArrayInputStream(serverCert);
			try
			{
				java.security.cert.Certificate ca = cf.generateCertificate(caInput);

				// Create a KeyStore containing our trusted CAs
				String keyStoreType = KeyStore.getDefaultType();
				KeyStore keyStore = KeyStore.getInstance(keyStoreType);
				keyStore.load(null, null);
				keyStore.setCertificateEntry("ca", ca);

				// Create a TrustManager that trusts the CAs in our KeyStore
				String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
				tmf.init(keyStore);

				context.init(null, tmf.getTrustManagers(), null);
			}
			finally {caInput.close();}
		}
		
		SocketFactory sf = context.getSocketFactory();
		//skt = (SSLSocket) sf.createSocket(serverHost, serverPort);
		//s = skt.getSession();
		return (SSLSocket) sf.createSocket(serverHost, serverPort);

		//dont need CNAME verification; we are using a specific cert
	}
}
