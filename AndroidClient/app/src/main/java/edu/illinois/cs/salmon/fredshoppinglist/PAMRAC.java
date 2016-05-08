package edu.illinois.cs.salmon.fredshoppinglist;

import android.content.Context;
import android.content.Intent;
import android.text.style.AlignmentSpan;
import android.util.Base64;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by salmon on 4/5/16.
 */
public final class PAMRAC
{
    private static pamrac.Pamrac.InnerBlob currentSite = null;
    public static String masterPassword = null;
    private static pamrac.Pamrac.InnerPassworded crownJewels = null; //includes list of site names
    private static pamrac.Pamrac.MasterKeyPasswordedFile jewelrySafe = null; //ciphertext contains crownJewels

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
            reader = appContext.openFileInput("crownjewels.pbf");
            jewelrySafe = pamrac.Pamrac.MasterKeyPasswordedFile.parseFrom(reader);
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

    public static boolean sensitiveInfoIsUnlocked()
    {
        return HACK_SENSITIVE_INFO_UNLOCKED || (crownJewels != null && masterPassword != null);
    }

    public static String currentLabelFromKeycode(int keycode)
    {
        if(!ensureJewelrySafeLoaded())
            return "Set up PAMRAC";

        if(keycode == 58)
        {
            if(!sensitiveInfoIsUnlocked())
                return "";
            if(currentSite == null)
                return "Choose\nsite";
            else
                return "Choose\nnew site";
        }
        else if(keycode == 57)
        {
           return sensitiveInfoIsUnlocked() ?
                    "Lock\npasswords" :
                    "Unlock\npasswords";

        }
        else if(keycode == 56)
            return "Back to\nkeyboard";

        else if (sensitiveInfoIsUnlocked())
        {
            if(!choosingSite && currentSite != null)
            {
                int index = keycode - 48; //Keycodes start from 48, which is ASCII '0'.

                if(index >= currentSite.getFieldsCount())
                    return "NO KEY: " + index;
                else
                    return currentSite.getFields(index).getName();
            }
            else if(choosingSite)
            {
                //TODO need to give access to all sites....
                int index = keycode - 48; //Keycodes start from 48, which is ASCII '0'.
                if(crownJewels == null || index >= crownJewels.getSiteNamesCount())
                   return "NO SITE " + index;
                else
                    return crownJewels.getSiteNames(index);
            }
            else return "";
        }
        else return "";
    }

    public static String currentStringValFromKeycode(int keycode)
    {
        if(!PAMRAC.sensitiveInfoIsUnlocked())
            return "";

        int index = keycode - 48; //Keycodes start from 48, which is ASCII '0'.

        if(currentSite == null || index >= currentSite.getFieldsCount())
            return "NO STRINGVAL FOR INDEX " + index;
        else
            return currentSite.getFields(index).getValue();


    }

    public static String hashSitename(String siteName, byte[] filenamesalt)
    {
        try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(siteName.getBytes(StandardCharsets.UTF_8));
        md.update(filenamesalt);
        return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
        } catch(NoSuchAlgorithmException e) {return null;} //lol yeah sure no sha-256
    }

    private static void setCurrentSiteFromData(pamrac.Pamrac.BlobFile blobFile) throws Exception
    {
        //if this blob has a salt, derive key from that salt.
        //if it does NOT have salt, use crownJewels.getMasterKey()
        byte[] keyToUse = null;
        if(blobFile.hasSalt())
            keyToUse = derivePAMRACKey(masterPassword, blobFile.getSalt().toByteArray());
        else
            keyToUse = crownJewels.getMasterKey().toByteArray();

        com.google.protobuf.ByteString ciphertextBS = blobFile.getInnerBlobCiphertext();
        com.google.protobuf.ByteString initVectorBS = blobFile.getAesInitVector();

        byte[] innerBlobRaw = decrypt(ciphertextBS.toByteArray(), keyToUse, initVectorBS.toByteArray());
        currentSite = pamrac.Pamrac.InnerBlob.parseFrom(innerBlobRaw);
    }

    //Try decrypting the specified blob, to be loaded into currentSite. If there is no file with
    //the expected hashed name, try getting a blobs update from the server. If that doesn't get you
    //the expected file, then give up.
    public static void setCurrentSite(String siteName, Context context) throws Exception
    {
        if(crownJewels == null)
            throw new Exception("No crown jewels present with which to decrypt the blob of"+siteName);

        String hashedSiteName = hashSitename(siteName, crownJewels.getFilenamesalt().toByteArray());

        FileInputStream blobReader;
        try
        {
            blobReader = context.openFileInput(hashedSiteName);
            pamrac.Pamrac.BlobFile blobFile = pamrac.Pamrac.BlobFile.parseFrom(blobReader);
            setCurrentSiteFromData(blobFile);
        }
        catch(FileNotFoundException e)
        {
            ServerDownload.retrieveBlobsFromServer();

            //if the file 'hashedSiteName' STILL does not exist, give up
            FileInputStream blobReader2;
            blobReader2 = context.openFileInput(hashedSiteName);
            //let openFileInput()'s FileNotFoundException propagate; we expected that file to exist!
            pamrac.Pamrac.BlobFile blobFile = pamrac.Pamrac.BlobFile.parseFrom(blobReader2);
            setCurrentSiteFromData(blobFile);
        }
    }

    public static void setMasterPassword(String masterPW)
    {
        masterPassword = masterPW;
    }

    //Thanks to https://gist.github.com/bricef/2436364.
    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] initVec)
    {
        try
        {
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
                    PAMRAC.SCRYPT_N, PAMRAC.SCRYPT_r, PAMRAC.SCRYPT_p, PAMRAC.AES_KEYLEN_BYTES);
        }
        catch(GeneralSecurityException e)
        {
            //TODO some error message or whatever
            return null;
        }
    }

    public static boolean unlockAllSensitiveInfo(Context appContext) throws Exception
    {
        if(masterPassword == null)
            return false;

        com.google.protobuf.ByteString saltBS = jewelrySafe.getSalt();
        com.google.protobuf.ByteString ciphertextBS = jewelrySafe.getInnerCiphertext();
        com.google.protobuf.ByteString initVectorBS = jewelrySafe.getAesInitVector();


        byte[] derivedKey = derivePAMRACKey(masterPassword, saltBS.toByteArray());
        if(derivedKey == null)
            return false;
        byte[] crownJewelsRaw = decrypt(ciphertextBS.toByteArray(), derivedKey, initVectorBS.toByteArray());
        if(crownJewelsRaw == null)
            return false;
        crownJewels = pamrac.Pamrac.InnerPassworded.parseFrom(crownJewelsRaw);

        HACK_SENSITIVE_INFO_UNLOCKED = true;
        return true;

    }

    public static void lockAllSensitiveInfo()
    {
        HACK_SENSITIVE_INFO_UNLOCKED = false;
        currentSite = null;
        masterPassword = null;
        crownJewels = null;
    }
}
