package com.example.hackeris.project;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.IBinder;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity implements View.OnClickListener {

    private DemoVPNService mVPNService;
    ListView domainNameAccessListView;
    private List<String> domainNameAccessList = new ArrayList<>();
    ArrayAdapter<String> domainNameAccessListAdapter;

    private ServiceConnection mServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mVPNService = ((DemoVPNService.VPNServiceBinder) service).getService();
            mVPNService.setMainActivity (MainActivity.this);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {

        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_demo_main);

        findViewById(R.id.btn_connect).setOnClickListener(this);
        findViewById(R.id.btn_disconnect).setOnClickListener(this);

        // Get ListView object from xml
        domainNameAccessListView = (ListView) findViewById(R.id.domainNameAccessListView);

        domainNameAccessListAdapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_list_item_1, android.R.id.text1, domainNameAccessList);

        domainNameAccessListView.setAdapter(domainNameAccessListAdapter);

        domainNameAccessListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            @Override
            public void onItemClick(AdapterView<?> parent, View view,
                                    int position, long id) {

                // ListView Clicked item index
                int itemPosition     = position;

                // ListView Clicked item value
                String  itemValue    = (String) domainNameAccessListView.getItemAtPosition(position);

                // Show Alert
                Toast.makeText(getApplicationContext(),
                        "Position :" + itemPosition + "  ListItem : " + itemValue, Toast.LENGTH_LONG)
                        .show();

            }
        });
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.btn_connect) {
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                onActivityResult(0, RESULT_OK, null);
            }
        } else if (id == R.id.btn_disconnect) {
            mVPNService.stopVPNService();
            Intent intent = new Intent(this, DemoVPNService.class);
            stopService(intent);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {

        if (result == RESULT_OK) {
            Intent intent = new Intent(this, DemoVPNService.class);
            startService(intent);
            bindService(intent, mServiceConnection, Context.BIND_AUTO_CREATE);
        }
    }

    public void addDomainNameAccessListEntry (String entry)
    {
        if (!domainNameAccessList.contains(entry)) {
            domainNameAccessList.add(entry);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    domainNameAccessListAdapter.notifyDataSetChanged();
                }
            });
        }
    }
}
