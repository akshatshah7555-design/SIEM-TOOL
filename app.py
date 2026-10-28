import streamlit as st
import pandas as pd
import json, io
from datetime import datetime

st.set_page_config(page_title='SentinelX | Threat Correlation Platform', page_icon='🛡️', layout='wide')
st.markdown('''<style>
.block-container{padding-top:1.2rem;max-width:1450px}.hero{padding:1.25rem 1.5rem;border-radius:16px;background:linear-gradient(115deg,#101827,#173c56,#14535a);color:#fff;margin-bottom:1rem}.hero h1{color:#fff;margin:0;font-size:2.15rem}.hero p{color:#d7e8f4;margin:.35rem 0 0}.metric-card{border:1px solid #d6dde5;padding:14px;border-radius:12px}.small{font-size:.88rem;opacity:.8}
</style>''', unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ SentinelX</h1><p>Explainable Cyber Threat Correlation & Response Platform</p><p class="small">Correlate security events • Build attack storylines • Prioritize incidents • Recommend evidence-led response</p></div>', unsafe_allow_html=True)

SAMPLE = '''timestamp,username,source_ip,event,status,asset,details
2026-10-28 09:00:01,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:12,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:20,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:29,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:40,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:02:11,akshay,198.51.100.23,login,success,vpn-gateway,successful login after failures
2026-10-28 09:04:02,akshay,198.51.100.23,privilege_change,success,identity-service,role changed to administrator
2026-10-28 09:05:18,mira,192.0.2.44,login,success,finance-portal,normal login
2026-10-28 09:07:00,mira,192.0.2.44,login,failed,finance-portal,expired password
2026-10-28 09:09:31,svc_backup,203.0.113.77,login,success,backup-server,service account login
2026-10-28 09:10:10,akshay,198.51.100.23,data_export,success,customer-db,bulk export initiated
2026-10-28 09:12:42,akshay,198.51.100.23,security_setting_change,success,identity-service,mfa disabled
2026-10-28 09:13:08,akshay,198.51.100.23,login,success,customer-db,access from same source
2026-10-28 09:15:21,dev,192.0.2.19,change,failed,prod-api,change without approval reference
'''
REQUIRED={'timestamp','username','source_ip','event','status'}

@st.cache_data
def load_sample(): return pd.read_csv(io.StringIO(SAMPLE))

def analyze(raw, threshold=4):
    df=raw.copy()
    missing=REQUIRED-set(df.columns)
    if missing: raise ValueError('Missing required CSV columns: '+', '.join(sorted(missing)))
    for c in ['username','source_ip','event','status']:
        df[c]=df[c].fillna('unknown').astype(str).str.strip()
    if 'asset' not in df: df['asset']='unspecified'
    if 'details' not in df: df['details']=''
    df['timestamp']=pd.to_datetime(df['timestamp'],errors='coerce')
    df=df.dropna(subset=['timestamp']).sort_values('timestamp').reset_index(drop=True)
    df['event_norm']=df['event'].str.lower().str.replace(' ','_',regex=False)
    df['status_norm']=df['status'].str.lower()
    alerts=[]
    def add(sev, rule, user, ip, rows, explanation, next_check, response, points):
        alerts.append({'severity':sev,'rule':rule,'entity':str(user),'source_ip':str(ip),'event_count':len(rows),'first_seen':rows.timestamp.min().strftime('%Y-%m-%d %H:%M:%S'),'last_seen':rows.timestamp.max().strftime('%Y-%m-%d %H:%M:%S'),'evidence_rows':', '.join(str(int(x)+2) for x in rows.index[:12]),'explanation':explanation,'next_validation':next_check,'recommended_action':response,'risk_score':min(100,points)})
    fail=df[(df.event_norm.isin(['login','authentication','auth'])) & df.status_norm.isin(['failed','failure','denied','blocked'])]
    for (u,ip),g in fail.groupby(['username','source_ip']):
        if len(g)>=threshold:
            add('HIGH','Repeated authentication failures',u,ip,g,f'{len(g)} failed authentication events for the same user and source; configured threshold is {threshold}.','Check whether a successful login followed these failures and confirm the source with the user.','Review identity-provider logs; consider a temporary protective control according to incident policy.',72+min(20,len(g)))
    # failure -> success from same user/IP within 20 minutes
    for (u,ip),g in df.groupby(['username','source_ip']):
        fg=g[g.status_norm.isin(['failed','failure','denied','blocked'])]
        sg=g[(g.status_norm.isin(['success','successful','allowed'])) & g.event_norm.isin(['login','authentication','auth'])]
        if not fg.empty and not sg.empty:
            for _,s in sg.iterrows():
                prior=fg[fg.timestamp.between(s.timestamp-pd.Timedelta(minutes=20),s.timestamp)]
                if len(prior)>=2:
                    add('CRITICAL','Failure-to-success sequence',u,ip,g[(g.timestamp>=prior.timestamp.min())&(g.timestamp<=s.timestamp)],f'{len(prior)} failed authentication attempts were followed by a successful login within 20 minutes from the same user/source pair. This pattern may indicate account compromise.','Validate MFA outcome, device identity, geolocation context and whether the user recognizes the session.','Escalate for analyst review; revoke sessions or reset credentials only under approved incident procedures.',92)
                    break
    for _,r in df[df.event_norm.isin(['privilege_change','role_change','privilege_escalation'])].iterrows():
        add('HIGH','Privilege or role change',r.username,r.source_ip,df.loc[[r.name]],f'Privilege-related event recorded on asset {r.asset}. Context: {r.details}.','Confirm an approved change/request and verify the actor had authority.','Review identity audit trail and remove unauthorized privilege only after validation.',78)
    for _,r in df[df.event_norm.isin(['data_export','bulk_download','mass_download','database_export'])].iterrows():
        add('HIGH','Potential bulk data movement',r.username,r.source_ip,df.loc[[r.name]],f'Data-export event observed on {r.asset}. A single event does not prove exfiltration.','Check export volume, business purpose, destination, and preceding authentication/privilege events.','Preserve relevant logs and escalate to the data owner for validation.',76)
    for _,r in df[df.event_norm.isin(['security_setting_change','mfa_disabled','logging_disabled'])].iterrows():
        add('HIGH','Security control configuration change',r.username,r.source_ip,df.loc[[r.name]],f'Security-related configuration change observed: {r.details}.','Confirm the change ticket, approver, and before/after configuration.','Verify logging and MFA posture; follow change-control and incident procedures.',82)
    for _,r in df[df.event_norm.isin(['change','deployment','config_change']) & df.status_norm.isin(['failed','denied','rejected'])].iterrows():
        add('MEDIUM','Failed or rejected change event',r.username,r.source_ip,df.loc[[r.name]],f'Change event on {r.asset} was marked {r.status}. Details: {r.details}.','Check the change record, approval reference and deployment logs.','Investigate repeated attempts and reconcile with the authorized change calendar.',48)
    # Correlate all alerts into user/IP storylines; avoid duplicate identical rule alerts
    out=pd.DataFrame(alerts)
    if not out.empty:
        out=out.drop_duplicates(subset=['rule','entity','source_ip','first_seen']).sort_values('risk_score',ascending=False).reset_index(drop=True)
    return df,out

with st.sidebar:
    st.header('Investigation controls')
    threshold=st.slider('Failed-login alert threshold',3,10,4)
    source=st.radio('Data source',['Synthetic scenario','Upload CSV'],index=0)
    uploaded=st.file_uploader('Upload security events (.csv)',type=['csv']) if source=='Upload CSV' else None
    st.caption('Required columns: timestamp, username, source_ip, event, status. Optional: asset, details.')
    st.download_button('Download sample CSV',SAMPLE,file_name='sentinelx_sample_events.csv',mime='text/csv',use_container_width=True)
try:
    raw=pd.read_csv(uploaded) if source=='Upload CSV' and uploaded is not None else load_sample()
    if source=='Upload CSV' and uploaded is None: st.info('Upload a CSV to begin, or switch to Synthetic scenario for a guided demo.'); st.stop()
    events,alerts=analyze(raw,threshold)
except Exception as e:
    st.error(f'Unable to process input: {e}'); st.stop()

# Top navigation tabs
tabs=st.tabs(['Executive Overview','Event Explorer','Attack Storylines','Threat Context','Response Playbooks','Export & Methodology'])
with tabs[0]:
    st.subheader('Security posture at a glance')
    a,b,c,d=st.columns(4)
    a.metric('Events analysed',len(events)); b.metric('Alerts generated',len(alerts)); c.metric('High / Critical',int(alerts.severity.isin(['HIGH','CRITICAL']).sum()) if not alerts.empty else 0); d.metric('Unique users',events.username.nunique())
    st.markdown('#### Prioritized detections')
    if alerts.empty: st.success('No alerts generated for this input and threshold. This is not proof that the environment is secure.')
    else:
        view=alerts[['severity','rule','entity','source_ip','risk_score','explanation']].copy()
        st.dataframe(view,use_container_width=True,hide_index=True)
        st.markdown('#### Alert volume by detection type')
        st.bar_chart(alerts.groupby('rule').size().sort_values(ascending=False))
    st.caption('Risk scores are prototype prioritization scores, not calibrated probabilities of compromise.')
with tabs[1]:
    st.subheader('Normalized event explorer')
    c1,c2,c3=st.columns(3)
    users=['All']+sorted(events.username.unique().tolist()); selected_user=c1.selectbox('Filter user',users)
    event_types=['All']+sorted(events.event.unique().tolist()); selected_event=c2.selectbox('Filter event type',event_types)
    statuses=['All']+sorted(events.status.unique().tolist()); selected_status=c3.selectbox('Filter status',statuses)
    filt=events.copy()
    if selected_user!='All': filt=filt[filt.username==selected_user]
    if selected_event!='All': filt=filt.event==selected_event
    if selected_status!='All': filt=filt.status==selected_status
    st.dataframe(filt.drop(columns=['event_norm','status_norm'],errors='ignore'),use_container_width=True,hide_index=True)
    st.caption(f'Showing {len(filt)} of {len(events)} valid timestamped events.')
with tabs[2]:
    st.subheader('Attack Storyline Engine')
    st.write('This prototype groups related detections by account and source IP, orders them by time, and shows the evidence that supports or weakens a suspected sequence.')
    if alerts.empty: st.info('No storylines available for this dataset.')
    else:
        pairs=alerts.assign(story=alerts.entity+' | '+alerts.source_ip)['story'].drop_duplicates().tolist()
        chosen=st.selectbox('Select investigation thread',pairs)
        user,ip=chosen.split(' | ',1)
        related=alerts[(alerts.entity==user)&(alerts.source_ip==ip)].sort_values('first_seen')
        st.markdown(f'**Investigation entity:** `{user}`  ·  **Source:** `{ip}`')
        for _,r in related.iterrows():
            with st.expander(f"{r['first_seen']} — {r['severity']}: {r['rule']}",expanded=True):
                st.write('**Evidence explanation:** '+r['explanation'])
                st.write('**Source CSV row(s):** '+r['evidence_rows'])
                st.write('**Next validation question:** '+r['next_validation'])
                st.write('**Recommended next step:** '+r['recommended_action'])
        st.info('Storyline association is based on shared username/source IP and event timestamps; it does not establish attribution or prove an attack.')
with tabs[3]:
    st.subheader('Threat context & indicator handling')
    st.write('SentinelX extracts observed source IPs and summarizes their activity. It does not label an IP malicious based only on its appearance.')
    context=events.groupby('source_ip').agg(events=('source_ip','size'),users=('username','nunique'),event_types=('event','nunique'),first_seen=('timestamp','min'),last_seen=('timestamp','max')).reset_index().sort_values('events',ascending=False)
    st.dataframe(context,use_container_width=True,hide_index=True)
    indicator=st.text_input('Inspect an indicator from this dataset (IP, username, or asset)')
    if indicator:
        subset=events[events.astype(str).apply(lambda col: col.str.contains(indicator,case=False,na=False)).any(axis=1)]
        st.write(f'{len(subset)} matching event(s)')
        st.dataframe(subset.drop(columns=['event_norm','status_norm'],errors='ignore'),use_container_width=True,hide_index=True)
    st.warning('No external threat-intelligence service is queried. Reserved sample IP ranges are used for safe demonstration; enrich real indicators only through authorized sources.')
with tabs[4]:
    st.subheader('Response playbooks')
    playbooks={
      'Repeated authentication failures':['Confirm account owner and source device.','Review identity-provider logs and MFA results.','Check whether failures are followed by success.','Apply lockout/session controls according to approved policy.','Record evidence and close only after validation.'],
      'Failure-to-success sequence':['Validate session/device and MFA outcome.','Review activity after successful authentication.','Contact account owner through a trusted channel.','Preserve relevant logs; contain account/session if confirmed.','Document timeline, scope, decisions and recovery.'],
      'Privilege or role change':['Locate change ticket and approval.','Confirm actor authorization and role assignment.','Review actions performed with elevated access.','Revoke unauthorized access under approved process.','Capture evidence and review least-privilege controls.'],
      'Potential bulk data movement':['Confirm business purpose and data owner approval.','Inspect volume, destination, and access trail.','Preserve logs and relevant system metadata.','Escalate to incident response/privacy teams as appropriate.','Document confirmed scope; avoid assuming exfiltration from one event.'],
      'Security control configuration change':['Verify approved change request and maintenance window.','Compare before/after settings.','Confirm MFA/logging remain effective.','Restore secure settings if unauthorized, following policy.','Review related events and document approval trail.']}
    selected=st.selectbox('Choose playbook',list(playbooks.keys()))
    st.markdown('#### Analyst checklist')
    for i,step in enumerate(playbooks[selected]): st.checkbox(step,key=f'{selected}_{i}')
    st.caption('Playbooks are decision support. Analysts must follow organizational authorization and incident procedures.')
with tabs[5]:
    st.subheader('Export investigation artefacts')
    report={'product':'SentinelX','generated_at':datetime.utcnow().isoformat()+'Z','event_count':len(events),'alert_count':len(alerts),'method':'Deterministic rule-based event triage and user/source correlation','limitations':['Synthetic data may be used','No live SIEM ingestion','No external threat-intelligence lookup','Risk scores are not calibrated probabilities','Correlated events do not prove attribution'], 'alerts':alerts.to_dict(orient='records') if not alerts.empty else []}
    st.download_button('Download alert report (JSON)',json.dumps(report,indent=2,default=str),file_name='sentinelx_investigation_report.json',mime='application/json')
    st.download_button('Download detections (CSV)',alerts.to_csv(index=False) if not alerts.empty else 'severity,rule,entity,source_ip\n',file_name='sentinelx_alerts.csv',mime='text/csv')
    st.markdown('#### Methodology and scope')
    st.markdown('''- **Inputs:** timestamped event CSVs with username, source IP, event, and status fields.\n- **Detection:** configurable failed-login threshold; failure-to-success sequence within a 20-minute window; privilege changes; data-export events; security-setting changes; rejected change events.\n- **Explainability:** each alert includes the rule, supporting event rows, rationale, next validation question, and recommended response.\n- **Novelty claim to validate:** evidence-linked storyline grouping plus a next-validation prompt, compared with independent rule alerts on a labelled synthetic dataset. This is a proposed design contribution, not a claim of market-wide uniqueness.\n- **Limitations:** not a production SIEM, no endpoint telemetry, no automated containment, and no external IOC reputation feed.''')

st.divider()
st.caption('SentinelX academic prototype • Use synthetic or authorized data only • Validate findings before taking response action')
