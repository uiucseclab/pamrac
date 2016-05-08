package edu.illinois.cs.salmon.fredshoppinglist;

import java.util.Scanner;

public class ConsoleInterface
{
	public static void main(String[] args) throws Exception
	{
		if(args.length < 1)
		{
			System.out.println("Please give the server's IPaddr:port as an argument!");
			return;
		}
		
		System.out.println("How to test: run three instances of this program, each in a different");
		System.out.println("working directory. Run alice, then bob, then carol. Please indicate if ");
		System.out.println("this is alice, bob, or carol's instance:");
		Scanner scanner = new Scanner(System.in);
		String ourNick = scanner.nextLine();
		if(ourNick.indexOf("lice") >= 0)
		{
			ourNick = "alice";
			PAMRAC.connectNewStore(args[0], "HACKALICE", "alice", "alicepass");
			PAMRAC.KeyValuePair[] entry = new PAMRAC.KeyValuePair[2];
			entry[0] = new PAMRAC.KeyValuePair(); entry[1] = new PAMRAC.KeyValuePair();
			entry[0].name = "username"; entry[0].value = "alicefb";
			entry[1].name = "password"; entry[1].value = "alicefbpass";
			PAMRAC.updateAndUploadBlob("facebook.com", entry);
			PAMRAC.setCurrentSite("facebook.com");
			System.out.println("entries stored for this site: "+PAMRAC.listSiteObjects());
			System.out.println("username: "+PAMRAC.getSiteObject("username"));
			System.out.println("password: "+PAMRAC.getSiteObject("password"));
			
			System.out.println("Now run bob, get his public key fingerprint, and enter it here:");
			String bobfp = scanner.nextLine();
			System.out.println("Now run carol, get her public key fingerprint, and enter it here:");
			String carolfp = scanner.nextLine();
			
			PAMRAC.makeFriend("bob", bobfp, args[0]);
			PAMRAC.makeFriend("carol", carolfp, args[0]);
			
			String[] cmonjava = new String[1]; cmonjava[0] = "carol";
			String[] cmonjava2 = new String[1]; cmonjava2[0] = "bob";
			PAMRAC.generateAndUploadShares(cmonjava, cmonjava2, 2);
		}
		else if(ourNick.indexOf("ob") >= 0)
		{
			ourNick = "bob";
			PAMRAC.connectNewStore(args[0], "HACKBOB", "bob", "bobpass");
			
			System.out.println("(don't do this until alice is done):");
			System.out.println("enter alice's fingerprint here:");
			String alicefp = scanner.nextLine();
			System.out.println("Now run carol, get her public key fingerprint, and enter it here:");
			String carolfp = scanner.nextLine();
			
			PAMRAC.makeFriend("alice", alicefp, args[0]);
			PAMRAC.makeFriend("carol", carolfp, args[0]);
			
			PAMRAC.uploadShareToOther("alice", "carol");
		}
		else if(ourNick.indexOf("arol") >= 0)
		{
			ourNick = "carol";
			PAMRAC.connectNewStore(args[0], "HACKCAROL", "carol", "carolpass");
			
			System.out.println("(don't do this until alice and bob are done):");
			System.out.println("enter alice's fingerprint here:");
			String alicefp = scanner.nextLine();
			System.out.println("enter bob's fingerprint here:");
			String bobfp = scanner.nextLine();
			
			PAMRAC.makeFriend("alice", alicefp, args[0]);
			PAMRAC.makeFriend("bob", bobfp, args[0]);
			
			System.out.println("retrieved for alice: "+PAMRAC.reconstructFriend("alice"));
		}
		else
		{
			System.out.println("Please enter alice, bob, or carol.");
			return;
		}
	}	
}
