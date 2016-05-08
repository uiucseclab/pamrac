package edu.illinois.cs.salmon.fredshoppinglist;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.widget.TextView;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class DisplayMessageActivity extends AppCompatActivity {

    protected String readFileMessage()
    {
        try
        {
            FileInputStream reader = openFileInput("saved.txt");
            //byte[] buffer = new byte[reader.available()];
            //reader.read(buffer);
            StringBuilder builder = new StringBuilder();
            int ch;
            while((ch = reader.read())!= -1)
            {
                builder.append((char)ch);
            }
            reader.close();
            return builder.toString();
            //return buffer.toString();
        }
        catch(FileNotFoundException e)
        {
            return "FILE NOT FOUND OH NO";
        }
        catch(IOException e)
        {
            return "FILE IS MESSED UP OH NO";
        }
    }

    protected void saveMessage(String message)
    {
        try
        {
            FileOutputStream writer = openFileOutput("saved.txt", Context.MODE_PRIVATE);
            writer.write(message.getBytes());
            writer.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }










    protected String readProtoBuf()
    {
        try
        {
            FileInputStream reader = openFileInput("saved.pbf");

            pamrac.Pamrac.PAMRACMessage parsed = pamrac.Pamrac.PAMRACMessage.parseFrom(reader);

            reader.close();

            if(!parsed.getType().equals(pamrac.Pamrac.PAMRACMessage.Type.INIT_UPLOAD_REQUEST))
                return "ITS NOT AN UPLOAD REQUEST DUDE!";

            pamrac.Pamrac.InitUploadRequest ur = parsed.getInitUploadRequest();
            return ur.getHashedFilename() + ": " + ur.getProposedVersion();
        }
        catch(FileNotFoundException e)
        {
            return "FILE NOT FOUND OH NO";
        }
        catch(IOException e)
        {
            return "FILE IS MESSED UP OH NO";
        }
    }

    protected void saveProtoBuf(String theString)
    {
        try
        {
            FileOutputStream writer = openFileOutput("saved.pbf", Context.MODE_PRIVATE);

            pamrac.Pamrac.PAMRACMessage message =
                    pamrac.Pamrac.PAMRACMessage.newBuilder()
                    .setType(pamrac.Pamrac.PAMRACMessage.Type.INIT_UPLOAD_REQUEST)
                    .setInitUploadRequest
                    (
                            pamrac.Pamrac.InitUploadRequest.newBuilder()
                            .setHashedFilename(theString)
                            .setProposedVersion(1337)
                            .build()
                    )
                    .build();

            message.writeTo(writer);
            writer.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }




    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display_message);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        Intent intent = getIntent();

        //TextView textViewRead = new TextView(this);
        //textViewRead.setTextSize(40);
        TextView textViewRead = (TextView)findViewById(R.id.from_file);
        textViewRead.setText("read from file: " + readProtoBuf());//readFileMessage());

        String message = intent.getStringExtra(MyActivity.EXTRA_MESSAGE);
        //TextView textView = new TextView(this);
        //textView.setTextSize(40);
        TextView textView = (TextView)findViewById(R.id.to_file);
        textView.setText("will save to file: " + message);

        //saveMessage(message);
        saveProtoBuf(message);

        //OOPS right, don't need to dynamically add them if they're already in there!
        //RelativeLayout layout = (RelativeLayout) findViewById(R.id.content);
        //layout.addView(textViewRead);
        //layout.addView(textView);

        /*FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });*/

        /*
        <android.support.design.widget.FloatingActionButton
        android:id="@+id/fab"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="bottom|end"
        android:layout_margin="@dimen/fab_margin"
        android:src="@android:drawable/ic_dialog_email" />
         */
    }

}
