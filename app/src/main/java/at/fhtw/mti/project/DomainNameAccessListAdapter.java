/*
 * Developed by David Fritz 2016.
 */

package at.fhtw.mti.project;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageButton;
import android.widget.TextView;

import at.fhtw.mti.project.project.R;

import java.util.List;

/**
 * Created by dfritz on 25/03/16.
 */
public class DomainNameAccessListAdapter extends ArrayAdapter<DomainNameAccessListModel> {

    private final List<DomainNameAccessListModel> list;
    private final Activity context;

    public DomainNameAccessListAdapter(Activity context, List<DomainNameAccessListModel> list) {
        super(context, R.layout.rowbuttonlayout, list);
        this.context = context;
        this.list = list;
    }

    static class ViewHolder {
        protected TextView text;
        protected ImageButton imageButton;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = null;
        if (convertView == null) {
            LayoutInflater inflator = context.getLayoutInflater();
            view = inflator.inflate(R.layout.rowbuttonlayout, null);
            final ViewHolder viewHolder = new ViewHolder();
            viewHolder.text = (TextView) view.findViewById(R.id.label);
            viewHolder.imageButton = (ImageButton) view.findViewById(R.id.imageButton);
            viewHolder.imageButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    DomainNameAccessListModel element = (DomainNameAccessListModel) viewHolder.imageButton
                            .getTag();
                    element.setBlacklisted(!element.isBlacklisted());
                    DomainNameAccessListAdapter.this.notifyDataSetChanged();
                }
            });
            view.setTag(viewHolder);
            viewHolder.imageButton.setTag(list.get(position));
        } else {
            view = convertView;
            ((ViewHolder) view.getTag()).imageButton.setTag(list.get(position));
        }
        ViewHolder holder = (ViewHolder) view.getTag();
        holder.text.setText(list.get(position).getDomainName());
        holder.imageButton.setImageResource(list.get(position).isBlacklisted() ? R.drawable.blacklisted : R.drawable.whitelisted);

        return view;
    }

}
