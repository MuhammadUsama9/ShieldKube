from kubernetes import client, config
try:
    config.load_incluster_config()
except:
    config.load_kube_config(config_file="/root/.kube/config")
v1 = client.CoreV1Api()
events = v1.list_event_for_all_namespaces().items
print(f"Total events: {len(events)}")
if len(events) > 0:
    for e in events[:3]:
        print(dir(e))
        get_time = lambda e: getattr(e, "last_timestamp", None) or getattr(e, "event_time", None) or getattr(e.metadata, "creation_timestamp", None)
        print(get_time(e))
