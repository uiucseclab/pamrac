package edu.illinois.cs.salmon.fredshoppinglist;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

public class MasterPasswordInput extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_master_password_input);
    }

    public void finishEnterMasterPW(View view) throws Exception
    {
        EditText editText = (EditText)findViewById(R.id.edit_master_pw);
        PAMRAC.setMasterPassword(editText.getText().toString());
        PAMRAC.unlockAllSensitiveInfo(this);
        finish();
    }
}
