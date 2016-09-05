package at.fhtw.mti.project;

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
import android.widget.ListView;

import at.fhtw.mti.project.project.R;

import java.util.ArrayList;

public class MainActivity extends Activity implements View.OnClickListener {

    private TracingVPNService mVPNService;
    private ListView domainNameAccessListView;

    public ArrayList<DomainNameAccessListModel> getDomainNameAccessList() {
        return domainNameAccessList;
    }

    private ArrayList<DomainNameAccessListModel> domainNameAccessList = new ArrayList<>();
    DomainNameAccessListAdapter domainNameAccessListAdapter;

    private ServiceConnection mServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mVPNService = ((TracingVPNService.VPNServiceBinder) service).getService();
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

        domainNameAccessListAdapter = new DomainNameAccessListAdapter(this, domainNameAccessList);

        domainNameAccessListView.setAdapter(domainNameAccessListAdapter);
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
            Intent intent = new Intent(this, TracingVPNService.class);
            stopService(intent);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {

        if (result == RESULT_OK) {
            Intent intent = new Intent(this, TracingVPNService.class);
            startService(intent);
            bindService(intent, mServiceConnection, Context.BIND_AUTO_CREATE);
        }
    }

    public void addDomainNameAccessListEntry (String entry)
    {
        DomainNameAccessListModel model = new DomainNameAccessListModel (entry);

        if (!domainNameAccessList.contains(model)) {
            domainNameAccessList.add(model);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    domainNameAccessListAdapter.notifyDataSetChanged();
                }
            });
        }
    }
}
