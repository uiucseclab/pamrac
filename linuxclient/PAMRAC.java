package edu.illinois.cs.salmon.fredshoppinglist;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.util.*;
import javax.net.ssl.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import com.google.protobuf.*;

import at.archistar.crypto.data.*;
import at.archistar.crypto.secretsharing.*;
import at.archistar.crypto.random.*;
import at.archistar.crypto.decode.*;
import at.archistar.crypto.math.gf256.*;
import at.archistar.crypto.math.*;





/**
 * Created by salmon on 4/5/16.
 */
public final class PAMRAC
{
	//TODO load at startup (from friendnamemap.pbf); it's not encrypted
	private static PAMRACProto.FriendNameMap allFriends = null;
	
	private static boolean currentSiteRetrievable = false; //the NOT of "current site has salt"
	private static PAMRACProto.InnerBlob currentSite = null;
	private static int currentSiteVersion = 0;
	public static String masterPassword = null;

	private static PAMRACProto.InnerPassworded crownJewels = null; //includes list of site names
	private static PAMRACProto.MasterKeyPasswordedFile jewelrySafe = null; //ciphertext contains crownJewels
	private static byte[] ownPublicFingerprint = null;
	//corresponding to the private key inside jewelrySafe
	private static PublicKey ourPublicKey = null;
	//the Java object version of the private key inside jewelrySafe
	private static PrivateKey ourPrivateKey = null;
	
	private static byte[] ownServerCert = null; //TODO load this at some point
	private static String ownServerAddr = null;
	
	//out here because it can come from either crownJewels or a recovery
	private static byte[] downloadsecret = null;
	
	private static boolean HACK_SENSITIVE_INFO_UNLOCKED = false;

	public static boolean choosingSite = false;



	public static final int SCRYPT_N = (2*2*2*2 * 2*2*2*2 * 2*2*2*2 * 2);
	public static final int SCRYPT_r = 8;
	public static final int SCRYPT_p = 1;
	public static final int AES_KEYLEN_BYTES = 32;
	public static final int AES_KEYLEN_BITS = 256;


	public static boolean ensureJewelrySafeLoaded()
	{
		if(jewelrySafe != null)
			return true;

		FileInputStream reader;
		try
		{
			reader = new FileInputStream("crownjewels.pbf");
			jewelrySafe = PAMRACProto.MasterKeyPasswordedFile.parseFrom(reader);
			reader.close();
			return true;
		}
		catch(FileNotFoundException e)
		{
			return false;
		}
		catch(IOException e)
		{
			return false;
		}
	}
	
	public static String hashSitename(String siteName, byte[] filenamesalt)
	{
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(siteName.getBytes(StandardCharsets.UTF_8));
			md.update(filenamesalt);
			return Base64.getEncoder().encodeToString(md.digest());//, Base64.NO_WRAP);
		}
		catch(NoSuchAlgorithmException e)
		{
			return null;   //lol yeah sure no sha-256
		}
	}



	//Thanks to https://gist.github.com/bricef/2436364.
	public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] initVec)
	{
		try
		{
			//TODO UGH MIGHT BE 128, NOT 256.... although actually that's ok, 
			//since we will always just use the java library anyways
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
			SecretKeySpec keyObj = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, keyObj, new IvParameterSpec(initVec));
			return cipher.doFinal(plaintext);
		}
		catch(GeneralSecurityException e)
		{
			//TODO some error message or whatever
			return null;
		}
	}

	public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] initVec)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
			SecretKeySpec keyObj = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, keyObj, new IvParameterSpec(initVec));
			return cipher.doFinal(ciphertext);
		}
		catch(GeneralSecurityException e)
		{
			//TODO some error message or whatever
			return null;
		}
	}

	public static byte[] derivePAMRACKey(String password, byte[] salt)
	{
		byte[] pwAsBytes;
		try
		{
			pwAsBytes = password.getBytes(StandardCharsets.UTF_8);
			return Scrypt.scrypt(pwAsBytes, salt,
							PAMRAC.SCRYPT_N, PAMRAC.SCRYPT_r, PAMRAC.SCRYPT_p,
							PAMRAC.AES_KEYLEN_BYTES);
		}
		catch(GeneralSecurityException e)
		{
			//TODO some error message or whatever
			return null;
		}
	}

	public static byte[] getOwnServerCert() throws Exception
	{
		if(ownServerCert != null)
			return ownServerCert;
		
		FileInputStream addrReader = new FileInputStream("servercert.crt");
		int flen = addrReader.available();
		ownServerCert = new byte[flen];
		addrReader.read(ownServerCert);
		addrReader.close();
		
		return ownServerCert;
		
	}
	
	public static String getOwnServerAddr() throws Exception
	{
		if(ownServerAddr != null)
			return ownServerAddr;
		
		FileInputStream addrReader = new FileInputStream("serveraddr.txt");
		int flen = addrReader.available();
		byte[] rawIn = new byte[flen];
		addrReader.read(rawIn);
		addrReader.close();
		
		ownServerAddr = new String(rawIn, StandardCharsets.UTF_8);
		return ownServerAddr;
	}

	//input should be the whole x509 encoded file.
	//fingerprint is first 16 bytes of sha256(data).
	private static byte[] fprintOfPubkey(ByteString pubkeyBytes) throws Exception
	{
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(pubkeyBytes.toByteArray());
			byte[] ret16 = new byte[16];
			byte[] fullHash = md.digest();
			for(int i=0; i<16; i++)
				ret16[i] = fullHash[i];
			return ret16;
		}
		catch(NoSuchAlgorithmException e)
		{
			return null;   //lol yeah sure no sha-256
		}
	}
	//input should be the whole x509 encoded file.
	//returns base64(first 16 bytes of sha256(data))
	private static String base64FprintOfPubkey(ByteString pubkeyBytes) throws Exception
	{
		byte[] rawFP = fprintOfPubkey(pubkeyBytes);
		return Base64.getEncoder().encodeToString(rawFP);//, Base64.NO_WRAP);
	}

	public static void setMasterPassword(String masterPW)
	{
		masterPassword = masterPW;
	}
	
	public static byte[] signSomething(byte[] data) throws Exception
	{
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);
		rsaSigObj.update(data, 0, data.length);
		return rsaSigObj.sign();
	}
	public static byte[] signSomethingPlusNonce(byte[] dlsecret, byte[] nonce) throws Exception
	{
		byte[] overall = new byte[dlsecret.length + nonce.length];
		System.arraycopy(dlsecret, 0, overall, 0, dlsecret.length);
		System.arraycopy(nonce, 0, overall, dlsecret.length, nonce.length);
		return signSomething(overall);
	}
	
	private static byte[] hashOfFile(String filename) throws Exception
	{
		try
		{
			FileInputStream reader = new FileInputStream(filename);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			byte[] curChunk = new byte[4096];
			int curBytesRead = 0;
			while((curBytesRead = reader.read(curChunk)) != -1)
				md.update(curChunk, 0, curBytesRead);

			reader.close();
			return md.digest();
		}
		catch(NoSuchAlgorithmException e)
		{
			return null;   //lol yeah sure no sha-256
		}
	}
	private static byte[] computeAllFilesHashXOR() throws Exception
	{
		byte[] xorTotal = new byte[32];
		for(int i=0; i<xorTotal.length; i++)
			xorTotal[i] = 0;
		
		File blobsDir = new File("blobs");
		File[] blobsDirFiles = blobsDir.listFiles();
		for(int i=0; i<blobsDirFiles.length; i++)
		{
			 byte[] temp = hashOfFile(blobsDirFiles[i].getPath());
			 for(int j=0; j<xorTotal.length; j++)
				 xorTotal[j] ^= temp[j];
		}
		return xorTotal;
	}
	private static void updateSigByteString(Signature sigObj, ByteString bs) throws Exception
	{
		byte[] asArray = bs.toByteArray();
		sigObj.update(asArray, 0, asArray.length);
	}
	private static void updateSigString(Signature sigObj, String theStr) throws Exception
	{
		byte[] asArray = theStr.getBytes(StandardCharsets.UTF_8);
		sigObj.update(asArray, 0, asArray.length);
	}
	//sig is of:
	//	for each revoke_id:
	//		SHA256Update(revoke_id.[originator~owner~encryptedTo])
	//	for each share:
	//		SHA256Update(toString(share.timestamp))
	//		if(share has a masterkey_retrievable_file)
	//			SHA256Update(share.mkey_ret_file.[toString(timestamp)~initvec~ciphertext])
	//		if(share has a encrypted_initiator_mask)
	//			SHA256Update(share.encrypted_initiator_mask)
	//		SHA256Update(share.encrypted_share)
	//		SHA256Update(share.share_id.[originator~owner~encryptedTo])
	//	SHA256Update(nonce)
	//	SHA256Finish()
	private static byte[] signShareUpload(PAMRACProto.ShareUpload theUpload, byte[] nonce) throws Exception
	{
		//NOTE signSomething() would be awkward here; needs a single array
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);

		for(int i=0; i<theUpload.getRevokeIdCount(); i++)
		{
			PAMRACProto.ShareID curID = theUpload.getRevokeId(i);
			updateSigByteString(rsaSigObj, curID.getOriginatorFingerprint());
			updateSigByteString(rsaSigObj, curID.getOwnerFingerprint());
			updateSigByteString(rsaSigObj, curID.getEncryptedToFingerprint());
		}
		for(int i=0; i<theUpload.getShareCount(); i++)
		{
			PAMRACProto.KeyShare curShare = theUpload.getShare(i);
			
			updateSigString(rsaSigObj, Long.toString(curShare.getTimestamp()));
			
			if(curShare.hasMasterkeyRetrievableFile())
			{
				PAMRACProto.MasterKeyRetrievableFile mkrf = curShare.getMasterkeyRetrievableFile();
				updateSigString(rsaSigObj, Long.toString(mkrf.getTimestamp()));
				updateSigByteString(rsaSigObj, mkrf.getAesInitVector());
				updateSigByteString(rsaSigObj, mkrf.getInnerRetrievableCiphertext());
			}
			if(curShare.hasEncryptedInitiatorMask())
				updateSigByteString(rsaSigObj, curShare.getEncryptedInitiatorMask());
			
			updateSigByteString(rsaSigObj, curShare.getEncryptedShare());
			
			PAMRACProto.ShareID curID = curShare.getShareId();
			updateSigByteString(rsaSigObj, curID.getOriginatorFingerprint());
			updateSigByteString(rsaSigObj, curID.getOwnerFingerprint());
			updateSigByteString(rsaSigObj, curID.getEncryptedToFingerprint());
		}
		rsaSigObj.update(nonce, 0, nonce.length);
		return rsaSigObj.sign();
	}
	
	//NOTE not supposed to have a nonce
	private static byte[] signShareList(PAMRACProto.ShareList list) throws Exception
	{
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);
		updateSigString(rsaSigObj, Long.toString(list.getTimestamp()));
		updateSigString(rsaSigObj, Long.toString(list.getThreshold()));
		
		for(int i=0; i<list.getRecipientsCount(); i++)
		{
			if(list.getRecipients(i).hasNickname())
				updateSigString(rsaSigObj, list.getRecipients(i).getNickname());
			updateSigByteString(rsaSigObj, list.getRecipients(i).getFingerprint());
			updateSigString(rsaSigObj, list.getRecipients(i).getInitiator() 
									? new String("1") : new String("0"));
		}
		return rsaSigObj.sign();
	}
	
	private static byte[] signBlobUpload(PAMRACProto.BlobUpload upload, byte[] nonce) throws Exception
	{
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);
		
		updateSigString(rsaSigObj, upload.getHashedFilename());
		if(upload.getBlob().hasSalt())
			updateSigByteString(rsaSigObj, upload.getBlob().getSalt());
		updateSigString(rsaSigObj, Long.toString(upload.getBlob().getVersion()));
		updateSigByteString(rsaSigObj, upload.getBlob().getAesInitVector());
		updateSigByteString(rsaSigObj, upload.getBlob().getInnerBlobCiphertext());
		rsaSigObj.update(nonce, 0, nonce.length);
		return rsaSigObj.sign();
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	//will run as:    ./javapamraclient path/to/clientdir
	//TODO TODO
	//TO BE DONE:
	public static void connectNewStore(String serverAddr, String passcode, 
								String myNickname, String masterPW) throws Exception
	{
		//Generate and/or unlock the crown jewels, if necessary. 
		//Both generateCrownJewels() and unlockAllSensitiveInfo() result in crownJewels, ourPrivateKey,
		//and ourPublicKey all being loaded. 
		masterPassword = masterPW;
		if(jewelrySafe == null)
			generateCrownJewels(masterPW);
		else
			unlockAllSensitiveInfo();

		PAMRACProto.PAMRACMessage message =
		    PAMRACProto.PAMRACMessage.newBuilder()
		    .setType(PAMRACProto.PAMRACMessage.Type.CONNECT_TO_NEW_STORE)
		    .setConnectToNewStore
		    (
		        PAMRACProto.ConnectToNewStore.newBuilder()
		        .setPasscode(passcode)
		        .setPublicKey(ByteString.copyFrom(ourPublicKey.getEncoded()))
		        .setDownloadSecret(crownJewels.getDownloadsecret())
		        .setNickname(myNickname)
		        .setEncryptedMaster(jewelrySafe)
		        .build()
		    )
		    .setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		    .build();


		//save serverAddr
		FileOutputStream addrWriter = new FileOutputStream("serveraddr.txt");
		addrWriter.write(serverAddr.getBytes(StandardCharsets.UTF_8));
		addrWriter.close();

		FileOutputStream nickWriter = new FileOutputStream("mynickname.txt");
		nickWriter.write(myNickname.getBytes(StandardCharsets.UTF_8));
		nickWriter.close();

		SSLSocket tls = PTLS.connectTLS(serverAddr, getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		message.writeTo(tlsW);
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		tlsW.close(); tlsR.close(); tls.close();
		
		if(recvdMsg.getType() == PAMRACProto.PAMRACMessage.Type.NEW_STORE_CONNECT_RESULT && 
			recvdMsg.getNewStoreConnectResult().getSuccess())
		{
			System.out.println("Successfully connected to your new server at "+serverAddr);
		}
		else
			System.out.println("Failed to connect to your new server at "+serverAddr);
	}

	
	
	//Generates new crown jewels, or loads and unlocks them if they already exist.
	//Also loads ourPublicKey and ourPrivateKey.
	public static void generateCrownJewels(String masterPW) throws Exception
	{
		//first try loading from crownjewels.pbf
		PAMRACProto.MasterKeyPasswordedFile mkpf = null;
		try
		{
			FileInputStream reader = new FileInputStream("crownjewels.pbf");
			mkpf = PAMRACProto.MasterKeyPasswordedFile.parseFrom(reader);
			reader.close();
		}
		catch(Exception e){}
		
		if(mkpf != null)
		{
			jewelrySafe = mkpf;
			masterPassword = masterPW;
			unlockAllSensitiveInfo();
			return;
		}
		//====================================================
		//we do indeed need to generate brand new crown jewels
		
		//generate downloadsecret, filenamesalt, master key
		SecureRandom sr = new SecureRandom();
		byte[] dlsecret = new byte[32];
		byte[] filenamesalt = new byte[32];
		byte[] masterkey = new byte[32];
		sr.nextBytes(dlsecret);
		sr.nextBytes(filenamesalt);
		sr.nextBytes(masterkey);

		//generate keypair. Public key goes to ourpubkey.pub and ourPublicKey, private key goes
		//into crownJewels and ourPrivateKey.
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keypair = keyGen.genKeyPair();
		ourPublicKey = keypair.getPublic();
		ourPrivateKey = keypair.getPrivate();
		FileOutputStream pubkeyWriter = new FileOutputStream("ourpubkey.pub");
		pubkeyWriter.write(ourPublicKey.getEncoded());
		pubkeyWriter.close();
		
		System.out.println("Fingerprint of generated public key: "+base64FprintOfPubkey(ByteString.copyFrom(ourPublicKey.getEncoded())));
		
		ownPublicFingerprint = fprintOfPubkey(ByteString.copyFrom(ourPublicKey.getEncoded()));
		
		crownJewels = 
		PAMRACProto.InnerPassworded.newBuilder()
		        .setPrivateKey(ByteString.copyFrom(ourPrivateKey.getEncoded()))
		        .setDownloadsecret(ByteString.copyFrom(dlsecret))
			   .setFilenamesalt(ByteString.copyFrom(filenamesalt))
			   .setMasterKey(ByteString.copyFrom(masterkey))
		        .build();
		encryptInnerPasswordedToFile(crownJewels, "crownjewels.pbf"); 
	}

	private static void encryptInnerPasswordedToFile(PAMRACProto.InnerPassworded plainInner, 
										    String outFilename) throws Exception
	{
		//encrypt a jewelrySafe from plainInner
		byte[] jewelSalt = new byte[32];
		byte[] jewelIV = new byte[32];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(jewelSalt);
		sr.nextBytes(jewelIV);
		
		byte[] jewelKey = Scrypt.scrypt(masterPassword.getBytes(StandardCharsets.UTF_8), jewelSalt,
								  SCRYPT_N, SCRYPT_r, SCRYPT_p, 32);
		byte[] rawJewels = plainInner.toByteArray();
		byte[] encryptedJewels = encrypt(rawJewels, jewelKey, jewelIV);
		
		jewelrySafe = 
		PAMRACProto.MasterKeyPasswordedFile.newBuilder()
			.setSalt(ByteString.copyFrom(jewelSalt))
			.setAesInitVector(ByteString.copyFrom(jewelIV))
			.setInnerCiphertext(ByteString.copyFrom(encryptedJewels))
			.build();

		FileOutputStream writer = new FileOutputStream(outFilename);
		jewelrySafe.writeTo(writer);
		writer.close();
	}
	

	//Needs masterPassword set. Loads crownJewels, ourPrivateKey, ourPublicKey.
	public static boolean unlockAllSensitiveInfo() throws Exception
	{
		if(masterPassword == null)
			return false;

		ByteString saltBS = jewelrySafe.getSalt();
		ByteString ciphertextBS = jewelrySafe.getInnerCiphertext();
		ByteString initVectorBS = jewelrySafe.getAesInitVector();


		byte[] derivedKey = derivePAMRACKey(masterPassword, saltBS.toByteArray());
		if(derivedKey == null)
			return false;
		byte[] crownJewelsRaw = decrypt(ciphertextBS.toByteArray(), derivedKey, initVectorBS.toByteArray());
		if(crownJewelsRaw == null)
			return false;
		crownJewels = PAMRACProto.InnerPassworded.parseFrom(crownJewelsRaw);
		
		ourPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(
						new PKCS8EncodedKeySpec(crownJewels.getPrivateKey().toByteArray()));
		FileInputStream pubkeyReader = new FileInputStream("ourpubkey.pub");
		int flen = pubkeyReader.available();
		byte[] rawIn = new byte[flen];
		pubkeyReader.read(rawIn);
		pubkeyReader.close();
		ourPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(rawIn));

		ownPublicFingerprint = fprintOfPubkey(ByteString.copyFrom(ourPublicKey.getEncoded()));
		
		return true;
	}

	public static void lockAllSensitiveInfo()
	{
		currentSite = null;
		masterPassword = null;
		crownJewels = null;
	}

	public static String[] listSites() throws Exception
	{
		String[] retList = new String[crownJewels.getSiteNamesCount()];
		for(int i=0; i<crownJewels.getSiteNamesCount(); i++)
			retList[i] = crownJewels.getSiteNames(i);
		return retList;
	}

	private static void setCurrentSiteFromData(PAMRACProto.BlobFile blobFile) throws Exception
	{
		//if this blob has a salt, derive key from that salt.
		//if it does NOT have salt, use crownJewels.getMasterKey()
		byte[] keyToUse = null;
		if(blobFile.hasSalt())
			keyToUse = derivePAMRACKey(masterPassword, blobFile.getSalt().toByteArray());
		else
			keyToUse = crownJewels.getMasterKey().toByteArray();
		currentSiteRetrievable = !blobFile.hasSalt();

		ByteString ciphertextBS = blobFile.getInnerBlobCiphertext();
		ByteString initVectorBS = blobFile.getAesInitVector();

		byte[] innerBlobRaw = decrypt(ciphertextBS.toByteArray(), keyToUse, initVectorBS.toByteArray());
		currentSite = PAMRACProto.InnerBlob.parseFrom(innerBlobRaw);
		currentSiteVersion = blobFile.getVersion();
	}

	//Try decrypting the specified blob, to be loaded into currentSite. If there is no file with
	//the expected hashed name, try getting a blobs update from the server. If that doesn't get you
	//the expected file, then create an empty one.
	public static void setCurrentSite(String siteName) throws Exception
	{
		if(crownJewels == null)
			throw new Exception("No crown jewels present with which to decrypt the blob of"+siteName);

		String hashedSiteName = hashSitename(siteName, crownJewels.getFilenamesalt().toByteArray());

		try
		{
			FileInputStream blobReader;
			blobReader = new FileInputStream(hashedSiteName);
			PAMRACProto.BlobFile blobFile = PAMRACProto.BlobFile.parseFrom(blobReader);
			setCurrentSiteFromData(blobFile);
			blobReader.close();
		}
		catch(FileNotFoundException e)
		{
			downloadBlobs();

			//if the file 'hashedSiteName' STILL does not exist, create a new empty blob
			try
			{
				FileInputStream blobReader2 = new FileInputStream(hashedSiteName);
				//let openFileInput()'s FileNotFoundException propagate; we expected that file to exist!
				PAMRACProto.BlobFile blobFile = PAMRACProto.BlobFile.parseFrom(blobReader2);
				setCurrentSiteFromData(blobFile);
				blobReader2.close();
			}
			catch(FileNotFoundException e2)
			{
				currentSite = PAMRACProto.InnerBlob.newBuilder().setFilename(siteName).build();
				currentSiteVersion = 1;
			}
		}
	}

	//NOTE in the real thing, this loop will be scattered out over getLabelFromKeycode calls
	public static String[] listSiteObjects() throws Exception
	{
		String[] retList = new String[currentSite.getFieldsCount()];
		for(int i=0; i<currentSite.getFieldsCount(); i++)
			retList[i] = currentSite.getFields(i).getName();
		return retList;
	}

	//!!!THIS IS THE PASSWORD-INPUT EQUIVALENT!!!
	public static String getSiteObject(String objectName) throws Exception
	{
		for(int i=0; i<currentSite.getFieldsCount(); i++)
			if(currentSite.getFields(i).getName().equals(objectName))
				return currentSite.getFields(i).getValue();
		return "";
	}

	public static void downloadBlobs() throws Exception
	{
		SSLSocket tls = PTLS.connectTLS(getOwnServerAddr(), getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.InitBlobRequest theInitReq = PAMRACProto.InitBlobRequest.newBuilder()
										.setAllHashXor(
											ByteString.copyFrom(computeAllFilesHashXOR()))
										.build();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_BLOB_REQUEST)
		.setInitBlobRequest(theInitReq)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.InitBlobResponse theInitResp = recvdMsg.getInitBlobResponse();
		
		if(theInitResp.getXorMatches())
			return;
		
		byte[] nonce = theInitResp.getNonce().toByteArray();
		
		
		
      
		ArrayList<PAMRACProto.BlobRequest.BlobHash> alreadyHave 
				= new ArrayList<PAMRACProto.BlobRequest.BlobHash>();
		File blobsDir = new File("blobs");
		File[] blobsDirFiles = blobsDir.listFiles();
		for(int i=0; i<blobsDirFiles.length; i++)
		{
			alreadyHave.add(PAMRACProto.BlobRequest.BlobHash.newBuilder()
						.setBlobName(blobsDirFiles[i].getName())
						.setBlobHash(ByteString.copyFrom(hashOfFile(blobsDirFiles[i].getPath())))
						.build());
		}
		
		PAMRACProto.BlobRequest theReq = PAMRACProto.BlobRequest.newBuilder()
										.addAllCachedBlobs(alreadyHave)
										.setDownloadsecretProof(ByteString.copyFrom(
											signSomethingPlusNonce(downloadsecret, nonce)))
										.setProofNonce(ByteString.copyFrom(nonce))
										.build();
		

		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.BLOB_REQUEST)
		.setBlobRequest(theReq)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.BlobResponse theResp = recvdMsg2.getBlobResponse();
		tlsW.close(); tlsR.close(); tls.close();
		
		for(int i=0; i<theResp.getNewBlobsCount(); i++)
			writeBlobFile(theResp.getNewBlobs(i).getName(), theResp.getNewBlobs(i).getBlob());
	}
	
	
	private static void writeBlobFile(String hashedFilename, PAMRACProto.BlobFile theBlob) throws Exception
	{
		FileOutputStream writer = new FileOutputStream(hashedFilename);
		theBlob.writeTo(writer);
		writer.close();
		
		//Must also update the site_names field of crownJewels, so decrypt each blob to get its name.
		ArrayList<String> allSites = new ArrayList<String>();
		File blobsDir = new File("blobs");
		File[] blobsDirFiles = blobsDir.listFiles();
		for(int i=0; i<blobsDirFiles.length; i++)
		{
			FileInputStream blobReader = new FileInputStream(blobsDirFiles[i].getPath());
			PAMRACProto.BlobFile outer = PAMRACProto.BlobFile.parseFrom(blobReader);
			blobReader.close();
			
			//if this blob has a salt, derive key from that salt.
			//if it does NOT have salt, use crownJewels.getMasterKey()
			byte[] keyToUse = null;
			if(theBlob.hasSalt())
				keyToUse = derivePAMRACKey(masterPassword, theBlob.getSalt().toByteArray());
			else
				keyToUse = crownJewels.getMasterKey().toByteArray();
			currentSiteRetrievable = !theBlob.hasSalt();

			ByteString ciphertextBS = theBlob.getInnerBlobCiphertext();
			ByteString initVectorBS = theBlob.getAesInitVector();

			byte[] innerBlobRaw = decrypt(ciphertextBS.toByteArray(), keyToUse,
									initVectorBS.toByteArray());
			allSites.add(PAMRACProto.InnerBlob.parseFrom(innerBlobRaw).getFilename());
			//TODO filename is not a good name for that; should be sitename
		}
		
		crownJewels = setInnerPasswordedSiteNames(crownJewels, allSites);
		
		encryptInnerPasswordedToFile(crownJewels, "crownjewels.pbf");
	}
	
	private static PAMRACProto.InnerPassworded 
	setInnerPasswordedSiteNames(PAMRACProto.InnerPassworded theIP, ArrayList<String> allSites)
	 throws Exception
	{
		return PAMRACProto.InnerPassworded.newBuilder()
									.setMasterKey(theIP.getMasterKey())
									.setFilenamesalt(theIP.getFilenamesalt())
									.addAllSiteNames(allSites)
									.setDownloadsecret(theIP.getDownloadsecret())
									.setPrivateKey(theIP.getPrivateKey())
									.build();
	}

	private static PAMRACProto.InnerBlob setInnerBlobKeyValue(PAMRACProto.InnerBlob theIB,
													String name, String value) throws Exception
	{
		ArrayList<PAMRACProto.InnerBlob.KeyValue> allFields 
				= new ArrayList<PAMRACProto.InnerBlob.KeyValue>();
		
		for(int j=0; j<theIB.getFieldsCount(); j++)
		{
			if(theIB.getFields(j).getName().equals(name))
			{
				allFields.add(PAMRACProto.InnerBlob.KeyValue.newBuilder()
										.setName(name)
										.setValue(value)
										.build());
			}
			else
			{
				allFields.add(PAMRACProto.InnerBlob.KeyValue.newBuilder()
										.setName(theIB.getFields(j).getName())
										.setValue(theIB.getFields(j).getValue())
										.build());
			}
		}
		return PAMRACProto.InnerBlob.newBuilder()
								.setFilename(theIB.getFilename())
								.addAllFields(allFields)
								.build();
	}
	
	public static class KeyValuePair
	{
		public String name;
		public String value;
	}
	//TODO ideally, would be possible to delete a key-value pair out of the site....
	//	...but protocol buffers don't seem to straightforwardly support that? 
	//	and i'm too lazy to clear and rebuild.
	public static void updateAndUploadBlob(String siteName, KeyValuePair[] updatedContents) throws Exception
	{
		//First, we must have the site to be updated as the currently active one.
		setCurrentSite(siteName);
		//Update the site's values: modify or add. (TODO delete)
		for(int i=0; i<updatedContents.length; i++)
		{
			currentSite = setInnerBlobKeyValue(currentSite, updatedContents[i].name,
													updatedContents[i].value);
		}
		
		//Encrypt a serialization of currentSite, for the inner_blob_ciphertext of a BlobFile.
		SecureRandom sr = new SecureRandom();
		byte[] ivBytes = new byte[32];
			sr.nextBytes(ivBytes);
		
		PAMRACProto.BlobFile.Builder blobBuilder = PAMRACProto.BlobFile.newBuilder()
											.setVersion(1+currentSiteVersion)
											.setAesInitVector(ByteString.copyFrom(ivBytes));
		byte[] curSiteEncrypted = null;
		byte[] keyAES = null;
		byte[] curSiteBytes = currentSite.toByteArray();
		if(!currentSiteRetrievable)
		{
			byte[] saltBytes = new byte[32];
			sr.nextBytes(saltBytes);
			blobBuilder.setSalt(ByteString.copyFrom(saltBytes));
			keyAES = derivePAMRACKey(masterPassword, saltBytes);
		}
		else
		{
			keyAES = crownJewels.getMasterKey().toByteArray();
		}
		curSiteEncrypted = encrypt(curSiteBytes, keyAES, ivBytes);
		blobBuilder.setInnerBlobCiphertext(ByteString.copyFrom(curSiteEncrypted));
		
		PAMRACProto.BlobFile updatedCurBlobFile = blobBuilder.build();
		
		//write a local copy of the newly created BlobFile
		String hashedFileName = hashSitename(siteName, crownJewels.getFilenamesalt()
														  .toByteArray());
		writeBlobFile(hashedFileName, updatedCurBlobFile);
		
		//now upload
		
		SSLSocket tls = PTLS.connectTLS(getOwnServerAddr(), getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		

		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_BLOB_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.BlobUpload theReq = buildSignedBlobUpload(hashedFileName,
													updatedCurBlobFile,
													 nonce);
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.BLOB_UPLOAD)
		.setBlobUpload(theReq)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.BlobUploadResult theResp = recvdMsg2.getBlobUploadResult();
		tlsW.close(); tlsR.close(); tls.close();
		
		if(theResp.getVerificationOk() && theResp.getUploadSuccessful())
			System.out.println("Successfully updated, wrote, and uploaded "+siteName);
		else if(!theResp.getVerificationOk())
			System.out.println("Successfully updated and wrote "+siteName+", but upload failed: "+
							"server did not accept our signature.");
		else if(theResp.hasServerVersion())
			System.out.println("Successfully updated and wrote "+siteName+", but upload failed: "+
							"server wanted a version not equal to or lower than "+
							theResp.getServerVersion());
		else
			System.out.println("Successfully updated and wrote "+siteName+", but upload failed: "+
							"don't know why.");
	}
	
	private static PAMRACProto.BlobUpload buildSignedBlobUpload(String hashedFileName,
													PAMRACProto.BlobFile updatedCurBlobFile,
													 byte[] nonce) throws Exception
	{
		PAMRACProto.BlobUpload temp = 
		PAMRACProto.BlobUpload.newBuilder()
							.setHashedFilename(hashedFileName)
							.setBlob(updatedCurBlobFile)
							.setNonce(ByteString.copyFrom(nonce))
							.build();
		return PAMRACProto.BlobUpload.newBuilder()
						.setHashedFilename(hashedFileName)
						.setBlob(updatedCurBlobFile)
						.setNonce(ByteString.copyFrom(nonce))
						.setSignature(ByteString.copyFrom(signBlobUpload(temp, nonce)))
						.build();
	}
	
	private static class FriendEntryComparator implements Comparator<PAMRACProto.FriendNameMap.FriendNickname>
	{
		@Override 
		public int compare(PAMRACProto.FriendNameMap.FriendNickname a,
					    PAMRACProto.FriendNameMap.FriendNickname b)
		{
			byte[] afp = a.getFriendFingerprint().toByteArray();
			byte[] bfp = b.getFriendFingerprint().toByteArray();
			
			if(afp.length != bfp.length)
				return afp.length - bfp.length;
			
			for (int i=0; i<afp.length; i++)
			{
				int abyte = (int)afp[i] & (int)0xff;
				int bbyte = (int)bfp[i] & (int)0xff;
				if (abyte != bbyte) 
					return abyte - bbyte;
			}
			return 0;
		}
	}
	private static byte[] signFriendMap(PAMRACProto.FriendNameMap toSign) throws Exception
	{
		List<PAMRACProto.FriendNameMap.FriendNickname> allNames = toSign.getFriendsList();
		Collections.sort(allNames, new FriendEntryComparator());
		
		//Signing: toString(timestamp)~foreach friend:
		//[~name~friend_fprint~friend_pubkey~server_cert~server_address]
		
		//NOTE signSomething() would be awkward here; needs a single array
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);

		String timestampString = Long.toString(toSign.getTimestamp());
		byte[] timestampBytes = timestampString.getBytes(StandardCharsets.UTF_8);
		
		rsaSigObj.update(timestampBytes, 0, timestampBytes.length);
		for(int i=0; i<allNames.size(); i++)
		{
			updateSigString(rsaSigObj, allNames.get(i).getName());
			updateSigByteString(rsaSigObj, allNames.get(i).getFriendFingerprint());
			updateSigByteString(rsaSigObj, allNames.get(i).getFriendPubkey());
			updateSigByteString(rsaSigObj, allNames.get(i).getFriendServerCert());
			updateSigString(rsaSigObj, allNames.get(i).getServerAddress());
		}
		return rsaSigObj.sign();
	}
	private static PAMRACProto.FriendNameMap 
	addToFriendsAndSave(PAMRACProto.FriendNameMap friends, 
					PAMRACProto.FriendNameMap.FriendNickname theNewFriend) throws Exception
	{
		List<PAMRACProto.FriendNameMap.FriendNickname> friendNicks = friends.getFriendsList();
		friendNicks.add(theNewFriend);
		
		PAMRACProto.FriendNameMap temp = PAMRACProto.FriendNameMap.newBuilder()
								.addAllFriends(friendNicks)
								.setTimestamp(Calendar.getInstance().getTimeInMillis() / 1000L)
								.build();
								
		PAMRACProto.FriendNameMap ret = PAMRACProto.FriendNameMap.newBuilder()
								.addAllFriends(friendNicks)
								.setTimestamp(temp.getTimestamp())
								.setSignature(ByteString.copyFrom(signFriendMap(temp)))
								.build();
		
		FileOutputStream writeFriends = new FileOutputStream("friendnamemap.pbf");
		ret.writeTo(writeFriends);
		writeFriends.close();
		
		return ret;
	}

	//serverAddr should be like 1.2.3.4:443
	public static void makeFriend(String nickname, String pubkeyFprint, String serverAddr) throws Exception
	{
		SSLSocket tls = PTLS.connectTLS(serverAddr, null);
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.CONNECT_TO_FRIEND_SERVER)
		.setUserFingerprint(ByteString.copyFrom(Base64.getDecoder().decode(pubkeyFprint)))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.ConnectFriendServerResult theRes = recvdMsg.getConnectFriendServerResult();
		
		tlsW.close(); tlsR.close(); tls.close();
		
		//verify that theRes.sig_of_cert is a valid sig of theRes.server_cert, 
		//signed by user_public_key's private key.
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(theRes.getUserPublicKey().toByteArray());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey receivedPubKey = keyFactory.generatePublic(pubKeySpec);
		
		Signature sig = Signature.getInstance("SHA256withRSA", "SUN");
		sig.initVerify(receivedPubKey);
		byte[] serverCertBytes = theRes.getServerCert().toByteArray();
		sig.update(serverCertBytes, 0, serverCertBytes.length);
		boolean sigValid = sig.verify(theRes.getSigOfCert().toByteArray());
		
		if(sigValid && base64FprintOfPubkey(theRes.getUserPublicKey()).equals(pubkeyFprint))
		{
			PAMRACProto.FriendNameMap.FriendNickname theNewFriend =
				PAMRACProto.FriendNameMap.FriendNickname.newBuilder()
												.setName(nickname)
												.setFriendFingerprint(
							ByteString.copyFrom(Base64.getDecoder().decode(pubkeyFprint)))
												.setFriendServerCert(theRes.getServerCert())
												.setServerAddress(serverAddr)
												.build();
			allFriends = addToFriendsAndSave(allFriends, theNewFriend);
		}
		else
		{
			System.out.println("makeFriend failed for the following reason(s):");
			if(!sigValid)
				System.out.println("Signature of the foreign server's cert was not valid.");
			if(!base64FprintOfPubkey(theRes.getUserPublicKey()).equals(pubkeyFprint))
				System.out.println("The fingerprint you specified doesn't match the key the "
								+"foreign server presented us with.");
		}
	}

	public static void defriend(String nickname) throws Exception
	{
		boolean foundTarget = false;
		byte[] targetKeyFprint = null;
		
		PAMRACProto.FriendNameMap.Builder tempMap = PAMRACProto.FriendNameMap.newBuilder();
		List<PAMRACProto.FriendNameMap.FriendNickname> allNames = allFriends.getFriendsList();
		for(int i=0; i<allNames.size(); i++)
			if(!allNames.get(i).getName().equals(nickname))
				tempMap.addFriends(allNames.get(i));
			else
			{
				foundTarget = true;
				targetKeyFprint = allNames.get(i).getFriendFingerprint().toByteArray();
			}
		
		if(!foundTarget)
		{
			System.out.println(nickname+" not deleted; they were not found in the FriendNameMap!");
			return;
		}
		
		revokeShares(null, null, targetKeyFprint);
		
		Calendar rightNow = Calendar.getInstance();
		tempMap.setTimestamp(rightNow.getTimeInMillis() / 1000L);
		tempMap.setSignature(ByteString.copyFrom(signFriendMap(tempMap.build())));
		allFriends = tempMap.build();
		
		FileOutputStream writeFriends = new FileOutputStream("friendnamemap.pbf");
		allFriends.writeTo(writeFriends);
		writeFriends.close();
	}
	
	//TODO ensure [self] always has an entry in the map
	private static PAMRACProto.FriendNameMap.FriendNickname getFriendFromFP(byte[] fp)
	{
		for(int i=0; i<allFriends.getFriendsCount(); i++)
			if(allFriends.getFriends(i).getFriendFingerprint().toByteArray().equals(fp))
				return allFriends.getFriends(i);
		return null;
	}
	private static PAMRACProto.FriendNameMap.FriendNickname getFriendFromNick(String nick)
	{
		for(int i=0; i<allFriends.getFriendsCount(); i++)
			if(allFriends.getFriends(i).getName().equals(nick))
				return allFriends.getFriends(i);
		return null;
	}
	private static byte[] getFriendFPFromNick(String nick)
	{
		return getFriendFromNick(nick).getFriendFingerprint().toByteArray();
	}

	//Asks owner's server for a recovery share for originator. Must be friends with owner, 
	//so that we have their server addr on file.
	private static PAMRACProto.KeyShare retrieveShare(byte[] originatorFP, byte[] ownerFP) throws Exception
	{
		PAMRACProto.FriendNameMap.FriendNickname ownerInfo = getFriendFromFP(ownerFP);
		String serverAddr = ownerInfo.getServerAddress();
		byte[] serverCert = ownerInfo.getFriendServerCert().toByteArray();
		byte[] friendPubkey = ownerInfo.getFriendPubkey().toByteArray();
		
		SSLSocket tls = PTLS.connectTLS(serverAddr, serverCert);
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(ownerFP))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.ShareID theID = PAMRACProto.ShareID.newBuilder()
					.setOriginatorFingerprint(ByteString.copyFrom(originatorFP))
					.setOwnerFingerprint(ByteString.copyFrom(ownerFP))
					.setEncryptedToFingerprint(ByteString.copyFrom(ownPublicFingerprint))
					.build();
				
		
		//signature with requester private key of (originator_fp~owner_fp~encrypted_to_fp~nonce)
		Signature rsaSigObj = Signature.getInstance("SHA256withRSA", "SUN");
		rsaSigObj.initSign(ourPrivateKey);
		rsaSigObj.update(originatorFP, 0, originatorFP.length);
		rsaSigObj.update(ownerFP, 0, ownerFP.length);
		rsaSigObj.update(ownPublicFingerprint, 0, ownPublicFingerprint.length);
		byte[] requestSig = rsaSigObj.sign();
		
		PAMRACProto.ShareRequest theReq = PAMRACProto.ShareRequest.newBuilder()
											.setShareId(theID)
											.setNonce(ByteString.copyFrom(nonce))
											.setSignature(ByteString.copyFrom(requestSig))
											.build();
									
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(ownerFP))
		.setShareRequest(theReq)
		.build()
		.writeTo(tlsW);
		  
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		tlsW.close(); tlsR.close(); tls.close();
		return recvdMsg2.getKeyShare();
	}
	
	private static boolean fingerprintIsFriend(byte[] theFP) throws Exception
	{
		for(int i=0; i<allFriends.getFriendsCount(); i++)
			if(allFriends.getFriends(i).getFriendFingerprint().toByteArray().equals(theFP))
				return true;
		return false;
	}

	//From the given ShareList, return everyone whom we are friends with, and thus can 
	//expect to give us shares. (Our own share is included in this list).
	private static ArrayList<PAMRACProto.ShareList.ShareRecipient>
	selectFriendsFromShareList(PAMRACProto.ShareList allSharesList) throws Exception
	{
		ArrayList<PAMRACProto.ShareList.ShareRecipient> retList 
				= new ArrayList<PAMRACProto.ShareList.ShareRecipient>();
		for(int i=0; i<allSharesList.getRecipientsCount(); i++)
			if(fingerprintIsFriend(allSharesList.getRecipients(i).getFingerprint().toByteArray()))
				retList.add(allSharesList.getRecipients(i));
		return retList;
	}
	
	private static PAMRACProto.FriendNameMap.FriendNickname 
	lookupFriend(PAMRACProto.FriendNameMap friends, String nick) throws Exception
	{
		for(int i=0; i<friends.getFriendsCount(); i++)
			if(friends.getFriends(i).getName().equals(nick))
				return friends.getFriends(i);
		return null;
	}
	
	//Returns string to be printed: master key and dlsecret (both encoded in base64).
	public static String reconstructFriend(String friendNick) throws Exception
	{
		PAMRACProto.FriendNameMap.FriendNickname friend = lookupFriend(allFriends, friendNick);
		
		PAMRACProto.ShareList allSharesList 
				= retrieveOtherSharelist(friend.getFriendFingerprint().toByteArray(), 
									friend.getFriendPubkey().toByteArray(),
									friend.getServerAddress(), 
									friend.getFriendServerCert().toByteArray());
	
		//includes self
		ArrayList<PAMRACProto.ShareList.ShareRecipient> friendRecipients 
				= selectFriendsFromShareList(allSharesList);
		
		if(friendRecipients.size() < allSharesList.getThreshold())
		{
			return "Not friends with enough of "+friendNick+"'s recipients to reconstruct. "+
							"Including yourself, you would have "+
							Long.toString(friendRecipients.size())+"; need "+
							allSharesList.getThreshold();
		}
		
		boolean foundSelfInitiator = false;
		byte[] decryptedInitiatorMask = null;
		PAMRACProto.MasterKeyRetrievableFile mkrf = null;
		for(int i=0; i<friendRecipients.size(); i++)
			if(friendRecipients.get(i).getFingerprint().toByteArray().equals(ownPublicFingerprint))
				foundSelfInitiator = true;
		if(!foundSelfInitiator)
			return "You are not an initiator for "+friendNick;
		
		PAMRACProto.KeyShare ownShare = retrieveShare(friend.getFriendFingerprint().toByteArray(), 
											 ownPublicFingerprint);
		
		byte[] encryptedInitiatorMask = ownShare.getEncryptedInitiatorMask().toByteArray();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, ourPrivateKey);
		decryptedInitiatorMask = cipher.doFinal(encryptedInitiatorMask);
		mkrf = ownShare.getMasterkeyRetrievableFile();
		
		ArrayList<PAMRACProto.KeyShare> gottenShares = new ArrayList<PAMRACProto.KeyShare>();
		for(int i=0; i<friendRecipients.size() && gottenShares.size() < allSharesList.getThreshold(); i++)
		{
			PAMRACProto.KeyShare curShare 
					= retrieveShare(friend.getFriendFingerprint().toByteArray(),
								 allSharesList.getRecipients(i).getFingerprint().toByteArray());
			if(curShare != null)
				gottenShares.add(curShare);
		}
		
		if(gottenShares.size() < allSharesList.getThreshold())
		{
			return "Couldn't retrieve enough of "+friendNick+"'s recipients to reconstruct. "+
							"Including yourself, you got "+
							Long.toString(gottenShares.size())+"; need "+
							allSharesList.getThreshold();
		}
		
		byte[] maskedMKRFKey = combineShares(gottenShares, allSharesList.getRecipientsCount(),
												  allSharesList.getThreshold());
		byte[] MKRFKey = new byte[maskedMKRFKey.length];
		for(int i=0; i<maskedMKRFKey.length && i<decryptedInitiatorMask.length; i++)
			MKRFKey[i] = (byte)(maskedMKRFKey[i] ^ decryptedInitiatorMask[i]);
		
		byte[] innerRetrievableBytes = decrypt(mkrf.getInnerRetrievableCiphertext().toByteArray(), 
									  MKRFKey, mkrf.getAesInitVector().toByteArray());
		PAMRACProto.InnerRetrievable innerRetrievable 
				= PAMRACProto.InnerRetrievable.parseFrom(innerRetrievableBytes);
		return "Master key (base64): "+
				Base64.getEncoder().encodeToString(innerRetrievable.getMasterKey().toByteArray())+
				"\nDownload secret (base 64): "+
				Base64.getEncoder().encodeToString(innerRetrievable.getDOWNLOADSECRET().toByteArray());
	}
	
	//returns the key to a mkrf, but masked with the initiator mask
	private static byte[] combineShares(ArrayList<PAMRACProto.KeyShare> gottenShares, int n, int k)
	 throws Exception
	{
		if(k > gottenShares.size())
			throw new Exception("You didn't pass in as many shares as you said it takes!");
		
		GFFactory gffactory = new GF256Factory();
		ShamirPSS combiner = new
		ShamirPSS(n, k, new JavaSecureRandom(), new ErasureDecoderFactory(gffactory), 
			gffactory.createHelper());
		
		at.archistar.crypto.data.Share[] shares = new at.archistar.crypto.data.Share[k];
		for(int i=0; i<k; i++)
		{
			if(!gottenShares.get(i).getShareId().getEncryptedToFingerprint().toByteArray()
								.equals(ownPublicFingerprint))
			{
				throw new Exception("Not all of these shares we're combining are encrypted to us!");
			}
			byte[] encShare = gottenShares.get(i).getEncryptedShare().toByteArray();
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, ourPrivateKey);
			byte[] decShare = cipher.doFinal(encShare);
			shares[i] = ShareFactory.deserialize(decShare);
		}
		return combiner.reconstruct(shares);
	}
	
	public static void uploadShareToOther(String originatorNick, String newEncryptToNick) throws Exception
	{
		uploadShareToOther(getFriendFPFromNick(originatorNick), getFriendFPFromNick(newEncryptToNick));
	}
	
	//We are owner, and (until now) encrypted_to. We want to reencrypt, and upload the result
	//to the server of the new encrypted_to person. (So, that server will receive a share whose
	//originator is the one specified here, whose owner is [we the sender], and whose encrypted_to
	//is that server's client.)
	public static void uploadShareToOther(byte[] originatorFP, byte[] new_to_encrypt_to_FP) throws Exception
	{
		PAMRACProto.KeyShare ourShareOfThis = retrieveShare(originatorFP, ownPublicFingerprint);
		
		PAMRACProto.ShareID newID = PAMRACProto.ShareID.newBuilder()
									.setOriginatorFingerprint(ourShareOfThis.getShareId()
									.getOriginatorFingerprint())
									.setOwnerFingerprint(ourShareOfThis.getShareId()
									.getOwnerFingerprint())
									.setEncryptedToFingerprint(
										ByteString.copyFrom(ownPublicFingerprint))
									.build();
		
		PAMRACProto.FriendNameMap.FriendNickname encryptToNickname = getFriendFromFP(new_to_encrypt_to_FP);
		String targetServerAddr = encryptToNickname.getServerAddress();
		byte[] targetServerCert = encryptToNickname.getFriendServerCert().toByteArray();
		PublicKey newEncryptToPubkey 
				= KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec
							(encryptToNickname.getFriendPubkey().toByteArray()));
		
		byte[] ourEncryptedShare = ourShareOfThis.getEncryptedShare().toByteArray();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, ourPrivateKey);
		byte[] ourPlaintextShare = cipher.doFinal(ourEncryptedShare);
		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.ENCRYPT_MODE, newEncryptToPubkey);
		byte[] shareEncryptedToOther = cipher2.doFinal(ourPlaintextShare);
		
		//NOTE initiator does not give out their initiator stuff (mkrf and encrypted initiator mask)
		PAMRACProto.KeyShare newShare = PAMRACProto.KeyShare.newBuilder()
						.setTimestamp(ourShareOfThis.getTimestamp())
						.setShareId(newID)
						.setEncryptedShare(ByteString.copyFrom(shareEncryptedToOther))
						.build();
		
		SSLSocket tls = PTLS.connectTLS(targetServerAddr, targetServerCert);
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(new_to_encrypt_to_FP))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.ShareUpload temp = PAMRACProto.ShareUpload.newBuilder()
										.addShare(newShare)
										.setNonce(ByteString.copyFrom(nonce))
										.build();
		
		PAMRACProto.ShareUpload theUpload = PAMRACProto.ShareUpload.newBuilder()
								.addShare(newShare)
								.setNonce(ByteString.copyFrom(nonce))
								.setSignature(ByteString.copyFrom(signShareUpload(temp, nonce)))
								.build();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(new_to_encrypt_to_FP))
		.setShareUpload(theUpload)
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.ShareUploadResult theRes = recvdMsg2.getShareUploadResult();
		tlsW.close(); tlsR.close(); tls.close();
		
		if(!theRes.getVerificationOk())
			System.out.println("Give owned share to friend probably failed: "
							+"server said signature verification failed.");
	}
	
	private static PAMRACProto.MasterKeyRetrievableFile 
	generateMKRF(PAMRACProto.InnerPassworded crownJewels, long nowSSE, byte[] key) throws Exception
	{
		PAMRACProto.InnerRetrievable ir = PAMRACProto.InnerRetrievable.newBuilder()
									.setMasterKey(crownJewels.getMasterKey())
									.setDOWNLOADSECRET(crownJewels.getDownloadsecret())
									.build();			
		byte[] initVec = new byte[32];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(initVec);
		byte[] irEncrypted = encrypt(ir.toByteArray(), key, initVec);
		
		return PAMRACProto.MasterKeyRetrievableFile.newBuilder()
								.setTimestamp(nowSSE)
								.setAesInitVector(ByteString.copyFrom(initVec))
								.setInnerRetrievableCiphertext(ByteString.copyFrom(irEncrypted))
								.build();
	}
	
	private static PAMRACProto.ShareUpload generateAllKeyshares(String[] initiators, 
													String[] nonInitiators, 
													int k, byte[] nonce) throws Exception
	{
		long nowSSE = System.currentTimeMillis() / 1000l;
		
		at.archistar.crypto.math.GFFactory gffactory = new at.archistar.crypto.math.gf256.GF256Factory();
		at.archistar.crypto.secretsharing.ShamirPSS sharer = new at.archistar.crypto.secretsharing.ShamirPSS(initiators.length + nonInitiators.length, k, 
								   new at.archistar.crypto.random.JavaSecureRandom(), new at.archistar.crypto.decode.ErasureDecoderFactory(gffactory), 
								   gffactory.createHelper());
		
		byte[] sharedKey = new byte[32];
		byte[] initiatorMask = new byte[32];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(sharedKey);
		sr.nextBytes(initiatorMask);
		byte[] actualKey = new byte[32];
		for(int i=0; i<actualKey.length; i++)
			actualKey[i] = (byte)(sharedKey[i] ^ initiatorMask[i]);
		
		at.archistar.crypto.data.Share shares[] = sharer.share(sharedKey);
		
		PAMRACProto.MasterKeyRetrievableFile theMKRF = generateMKRF(crownJewels, nowSSE, actualKey);
		
		ArrayList<PAMRACProto.KeyShare> allPAMRACShares = new ArrayList<PAMRACProto.KeyShare>();
		int shareInd = 0;
		for(int i=0; i<initiators.length; i++,shareInd++)
		{
			PAMRACProto.FriendNameMap.FriendNickname curFriend = getFriendFromNick(initiators[i]);
			
			PublicKey newEncryptToPubkey 
				= KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec
							(curFriend.getFriendPubkey().toByteArray()));
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, newEncryptToPubkey);
			byte[] encryptedInitMask = cipher.doFinal(initiatorMask);
			byte[] encryptedShare = cipher.doFinal(shares[shareInd].serialize());
			
			PAMRACProto.KeyShare curShare 
				= PAMRACProto.KeyShare.newBuilder()
					.setTimestamp(nowSSE)
					.setMasterkeyRetrievableFile(theMKRF)
					.setEncryptedInitiatorMask(ByteString.copyFrom(encryptedInitMask))
					.setEncryptedShare(ByteString.copyFrom(encryptedShare))
					.setShareId(PAMRACProto.ShareID.newBuilder()
						.setOriginatorFingerprint(ByteString.copyFrom(ownPublicFingerprint))
						.setOwnerFingerprint(curFriend.getFriendFingerprint())
						.setEncryptedToFingerprint(curFriend.getFriendFingerprint())
					.build())
				.build();
			allPAMRACShares.add(curShare);
		}
		for(int i=0; i<nonInitiators.length; i++, shareInd++)
		{
			PAMRACProto.FriendNameMap.FriendNickname curFriend = getFriendFromNick(nonInitiators[i]);
			
			PublicKey newEncryptToPubkey 
				= KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec
							(curFriend.getFriendPubkey().toByteArray()));
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, newEncryptToPubkey);
			byte[] encryptedShare = cipher.doFinal(shares[shareInd].serialize());
			
			PAMRACProto.KeyShare curShare 
				= PAMRACProto.KeyShare.newBuilder()
				.setTimestamp(nowSSE)
				.setEncryptedShare(ByteString.copyFrom(encryptedShare))
				.setShareId(PAMRACProto.ShareID.newBuilder()
					.setOriginatorFingerprint(ByteString.copyFrom(ownPublicFingerprint))
					.setOwnerFingerprint(curFriend.getFriendFingerprint())
					.setEncryptedToFingerprint(curFriend.getFriendFingerprint())
				.build())
			.build();
			allPAMRACShares.add(curShare);
		}
		
		PAMRACProto.ShareList theList = generateShareList(initiators, nonInitiators, k, nowSSE);
		PAMRACProto.ShareUpload temp = PAMRACProto.ShareUpload.newBuilder()
								.addAllShare(allPAMRACShares)
								.setList(theList)
								.setNonce(ByteString.copyFrom(nonce))
								.build();
		PAMRACProto.ShareUpload ret = PAMRACProto.ShareUpload.newBuilder()
								.addAllShare(allPAMRACShares)
								.setList(theList)
								.setNonce(ByteString.copyFrom(nonce))
								.setSignature(ByteString.copyFrom(signShareUpload(temp, nonce)))
								.build();
		return ret;
	}
	
	private static PAMRACProto.ShareList generateShareList(String[] initiators, 
												String[] nonInitiators, 
												int k, long nowSSE) throws Exception
	{
		ArrayList<PAMRACProto.ShareList.ShareRecipient> allRecips = 
			new ArrayList<PAMRACProto.ShareList.ShareRecipient>();
		for(int i=0; i<initiators.length; i++)
		{
			PAMRACProto.ShareList.ShareRecipient curRecip =
				PAMRACProto.ShareList.ShareRecipient.newBuilder()
					.setNickname(initiators[i])
					.setFingerprint(ByteString.copyFrom(getFriendFPFromNick(initiators[i])))
					.setInitiator(true)
					.build();
			allRecips.add(curRecip);
		}
		PAMRACProto.ShareList temp = PAMRACProto.ShareList.newBuilder()
							.setTimestamp(nowSSE)
							.setThreshold(k)
							.addAllRecipients(allRecips)
							.build();
		PAMRACProto.ShareList ret = PAMRACProto.ShareList.newBuilder()
							.setTimestamp(nowSSE)
							.setThreshold(k)
							.addAllRecipients(allRecips)
							.setSignature(ByteString.copyFrom(signShareList(temp)))
							.build();
		return ret;
	}

	//TODO should periodically run, for rotation
	public static void generateAndUploadShares(String[] initiators, String[] nonInitiators, int k)
	 throws Exception
	{
		SSLSocket tls = PTLS.connectTLS(getOwnServerAddr(), getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.setShareUpload(generateAllKeyshares(initiators, nonInitiators, k, nonce))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.ShareUploadResult theRes = recvdMsg2.getShareUploadResult();
		tlsW.close(); tlsR.close(); tls.close();
		
		if(!theRes.getVerificationOk())
			System.out.println("Share upload probably failed: server said signature verification failed.");
	}
	
	//Asks our server to forget any share with orig/owner/encrypted_to fingerprint matching
	//the corresponding argument.
	private static void revokeShares(byte[] originatorFprint, byte[] ownerFprint, byte[] encToFprint)
	 throws Exception
	{
		if(originatorFprint == null)
		{
			originatorFprint = new byte[1];
			originatorFprint[0] = 0;
		}
		if(ownerFprint == null)
		{
			ownerFprint = new byte[1];
			ownerFprint[0] = 0;
		}
		if(encToFprint == null)
		{
			encToFprint = new byte[1];
			encToFprint[0] = 0;
		}
		
		SSLSocket tls = PTLS.connectTLS(getOwnServerAddr(), getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.ShareID revokeMe = PAMRACProto.ShareID.newBuilder()
										.setOriginatorFingerprint(ByteString.copyFrom(
											originatorFprint))
										.setOwnerFingerprint(ByteString.copyFrom(ownerFprint))
										.setEncryptedToFingerprint(ByteString.copyFrom(encToFprint))
										.build();
		
		PAMRACProto.ShareUpload temp = PAMRACProto.ShareUpload.newBuilder()
										.addRevokeId(revokeMe)
										.setNonce(ByteString.copyFrom(nonce))
										.build();
		PAMRACProto.ShareUpload theUpload 
			= PAMRACProto.ShareUpload.newBuilder()
						.addRevokeId(revokeMe)
						.setNonce(ByteString.copyFrom(nonce))
						.setSignature(ByteString.copyFrom(signShareUpload(temp, nonce)))
						.build();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_UPLOAD)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.setShareUpload(theUpload)
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg2 = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.ShareUploadResult theRes = recvdMsg2.getShareUploadResult();
		
		tlsW.close(); tlsR.close(); tls.close();
		
		if(!theRes.getVerificationOk())
			System.out.println("Revoke probably failed: server said signature verification failed.");
		else
			for(int i=0; i<theRes.getIdsRevokedCount(); i++)
				System.out.println("Revoked: "+shareIDToString(theRes.getIdsRevoked(i)));
	}
	
	public static String shareIDToString(PAMRACProto.ShareID id) throws Exception
	{
		return
		"originatorFP: "+
		Base64.getEncoder().encodeToString(id.getOriginatorFingerprint().toByteArray())+
		", ownerFP: "+
		Base64.getEncoder().encodeToString(id.getOwnerFingerprint().toByteArray())+
		", encryptedToFP: "+
		Base64.getEncoder().encodeToString(id.getEncryptedToFingerprint().toByteArray());
	}

	private static PAMRACProto.ShareList retrieveOwnSharelist() throws Exception
	{
		SSLSocket tls = PTLS.connectTLS(getOwnServerAddr(), getOwnServerCert());
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_LIST_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.ShareListRequest shareListReq = PAMRACProto.ShareListRequest.newBuilder()
									.setRequesterFingerprint(
										ByteString.copyFrom(ownPublicFingerprint))
									.setNonce(ByteString.copyFrom(nonce))
									.setSignature(ByteString.copyFrom(signSomethingPlusNonce(
												ownPublicFingerprint, nonce)))
									.build();
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_LIST_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(ownPublicFingerprint))
		.setShareListRequest(shareListReq)
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.ShareList toRet = PAMRACProto.ShareList.parseFrom(tlsR);
		tlsW.close(); tlsR.close(); tls.close();
		
		if(!verifyShareList(toRet, ourPublicKey))
			throw new Exception("Failed to verify our own share list retrieved from our server!!!");
		
		return toRet;
	}

	private static PAMRACProto.ShareList retrieveOtherSharelist(byte[] retrieveFromFP, 
													byte[] retrieveFromPubkey,
													String retrieveFromServer, 
													byte[] retrieveFromCert) throws Exception
	{
		SSLSocket tls = PTLS.connectTLS(retrieveFromServer, retrieveFromCert);
		OutputStream tlsW = tls.getOutputStream();
		InputStream tlsR = tls.getInputStream();
		
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.INIT_SHARE_LIST_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(retrieveFromFP))
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.PAMRACMessage recvdMsg = PAMRACProto.PAMRACMessage.parseFrom(tlsR);
		PAMRACProto.NonceResponse nonceResp = recvdMsg.getNonceResponse();
		byte[] nonce = nonceResp.getNonce().toByteArray();
		
		PAMRACProto.ShareListRequest shareListReq = PAMRACProto.ShareListRequest.newBuilder()
									.setRequesterFingerprint(
										ByteString.copyFrom(ownPublicFingerprint))
									.setNonce(ByteString.copyFrom(nonce))
									.setSignature(ByteString.copyFrom(signSomethingPlusNonce(
												ownPublicFingerprint, nonce)))
									.build();
		PAMRACProto.PAMRACMessage.newBuilder()
		.setType(PAMRACProto.PAMRACMessage.Type.SHARE_LIST_REQUEST)
		.setUserFingerprint(ByteString.copyFrom(retrieveFromFP))
		.setShareListRequest(shareListReq)
		.build()
		.writeTo(tlsW);
		
		PAMRACProto.ShareList toRet = PAMRACProto.ShareList.parseFrom(tlsR);
		tlsW.close(); tlsR.close(); tls.close();
		
		if(!verifyShareList(toRet, retrieveFromPubkey))
			throw new Exception("Failed to verify share list of "
							+Base64.getEncoder().encodeToString(retrieveFromFP)
							+" from server "+retrieveFromServer);
		
		return toRet;
	}

	private static boolean verifyShareList(PAMRACProto.ShareList list, PublicKey verifyWith) throws Exception
	{
		Signature sig = Signature.getInstance("SHA256withRSA", "SUN");
		sig.initVerify(verifyWith);
		
		//signature with originator's private key of:
		//(toString(timestamp), toString(threshold), <IFPRESENT(nickname), fprint, initiator ? 1 : 0>, ... )
		//NOTE those 1, 0 are ASCII. They are 1 byte.
		updateSigString(sig, Long.toString(list.getTimestamp()));
		updateSigString(sig, Long.toString(list.getThreshold()));
		for(int i=0; i<list.getRecipientsCount(); i++)
		{
			PAMRACProto.ShareList.ShareRecipient curRecip = list.getRecipients(i);
			if(curRecip.hasNickname())
				updateSigString(sig, curRecip.getNickname());
			updateSigByteString(sig, curRecip.getFingerprint());
			updateSigString(sig, curRecip.getInitiator() ? "1" : "0");
		}
		return sig.verify(list.getSignature().toByteArray());
	}

	private static boolean verifyShareList(PAMRACProto.ShareList list, byte[] verifyWith) throws Exception
	{
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(verifyWith);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey theKey = keyFactory.generatePublic(pubKeySpec);
		return verifyShareList(list, theKey);
	}

}

