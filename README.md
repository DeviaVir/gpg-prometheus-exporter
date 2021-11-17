# gpg-prometheus-exporter

A prom exporter for parsing expiration of (armored) GPG (public) key files.

## Metrics

```
# HELP gpg_subkeys_current Active GPG subkeys count: not expired at this time
# TYPE gpg_subkeys_current gauge
gpg_subkeys_current{name="chase.gpg"} 1
# HELP gpg_subkeys_future_1week Active GPG keys count: won't expire in a week
# TYPE gpg_subkeys_future_1week gauge
gpg_subkeys_future_1week{name="chase.gpg"} 1
# HELP gpg_subkeys_future_2weeks Active GPG keys count: won't expire in two weeks
# TYPE gpg_subkeys_future_2weeks gauge
gpg_subkeys_future_2weeks{name="chase.gpg"} 1
```

Use the `future` subsystem to inform users about keys that are about to expire.

## Docker

Usage example:

```
docker run -p 9111:9111 -e GPG_KEYS_FOLDER=/dev/shm/gpg -e HTTP_LISTENADDR=":9119" -it --rm deviavir/gpg-prometheus-exporter:latest
```
