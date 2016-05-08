package edu.illinois.cs.salmon.fredshoppinglist;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.inputmethodservice.InputMethodService;
import android.inputmethodservice.Keyboard;
import android.inputmethodservice.KeyboardView;
import android.os.Bundle;
import android.view.View;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;

import java.util.List;

public class PamracIME extends InputMethodService
        implements KeyboardView.OnKeyboardActionListener
{
    private KeyboardView kv;
    private Keyboard keyboard;

    @Override
    public void onKey(int primaryCode, int[] keyCodes) { }

    @Override
    public void onPress(int primaryCode)
    {
        if(!PAMRAC.ensureJewelrySafeLoaded())
        {
            Intent generateCrownJewelsIntent = new Intent(Intent.ACTION_DEFAULT);
            generateCrownJewelsIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK); //TODO supposedly this can mess with navigation, but currently seems necessary
            generateCrownJewelsIntent.setClassName("edu.illinois.cs.salmon.fredshoppinglist",
                    "edu.illinois.cs.salmon.fredshoppinglist.GenerateCrownJewels");
            startActivity(generateCrownJewelsIntent);

            PAMRAC.generateCrownJewels();
        }

        if(primaryCode == 56)
        {
            InputMethodManager imeManager = (InputMethodManager)getApplicationContext().getSystemService(INPUT_METHOD_SERVICE);
            imeManager.showInputMethodPicker();
        }
        else if(primaryCode == 57)
        {
            if(PAMRAC.sensitiveInfoIsUnlocked())
            {
                PAMRAC.lockAllSensitiveInfo();
            }
            else
            {
                Intent passwordInputIntent = new Intent(Intent.ACTION_EDIT);
                passwordInputIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK); //TODO supposedly this can mess with navigation, but currently seems necessary

                passwordInputIntent.setClassName("edu.illinois.cs.salmon.fredshoppinglist",
                        "edu.illinois.cs.salmon.fredshoppinglist.MasterPasswordInput");

                //startActivityForResult(passwordInputIntent, INPUT_MASTER_PASSWORD);
                startActivity(passwordInputIntent);
                //TODO unless i am mistaken, it's actually something in here that's crashing, not the PAMRAC.unlockAllSensitiveInfo(this); call
            }

            updateKeyboard();
        }
        else if(primaryCode == 58)
        {
            PAMRAC.choosingSite = true;
            updateKeyboard();
        }
        else if(PAMRAC.choosingSite)
        {
            PAMRAC.choosingSite = false;
            try{PAMRAC.setCurrentSite(PAMRAC.currentLabelFromKeycode(primaryCode), getApplication());}
            catch(Exception e){} //TODO some error message
            updateKeyboard();
        }
        else
        {
            InputConnection input_recvr = getCurrentInputConnection();
            input_recvr.commitText(PAMRAC.currentStringValFromKeycode(primaryCode), 1);
        }
    }

    //TODO TRIM
    //@Override
    //protected void onActivityResult(int requestCode, int resultCode, Intent data)
    //{
     //   if(requestCode == INPUT_MASTER_PASSWORD && resultCode == RESULT_OK)
      //  {
      //      //TODO TRIM
      //      //Bundle intent_extras = data.getExtras();
      //      //PAMRAC.unlockAllSensitiveInfo(intent_extras.getString("PAMRACMASTERPW"));
      //      //now expecting the MasterPasswordInput to just write to a global var
      //      PAMRAC.unlockAllSensitiveInfo();
     //   }
    //}

    @Override
    public void onRelease(int primaryCode){}
    @Override
    public void onText(CharSequence text){}
    @Override
    public void swipeDown(){}
    @Override
    public void swipeUp(){}
    @Override
    public void swipeLeft(){}
    @Override
    public void swipeRight(){}

    private void updateKeyboard()
    {
        List<Keyboard.Key> allKeys = keyboard.getKeys();
        for(Keyboard.Key key : allKeys)
            key.label = PAMRAC.currentLabelFromKeycode(key.codes[0]);

        kv.setKeyboard(keyboard);
        kv.setOnKeyboardActionListener(this);
    }

    @Override
    public View onCreateInputView()
    {
        kv = (KeyboardView)getLayoutInflater().inflate(R.layout.keyboard, null);
        keyboard = new Keyboard(this, R.xml.qwerty);

        updateKeyboard();
        kv.setPreviewEnabled(false);

        return kv;
    }
}
