# Scheduled benchmarks

This repo includes a runner-side scheduling bundle for repeated two-VPS
benchmarks:

- `scripts/generate_remote_schedule_configs.sh`
- `scripts/run_scheduled_benchmarks.sh`
- `ops/scheduled-benchmarks.env.example`
- `ops/systemd/tls-pq-bench-{track,full}.{service,timer}`

## Intended layout

- Server VPS: keep the benchmark server processes running continuously.
- Runner VPS: trigger scheduled `runner --config ...` batches every 4 hours,
  plus one daily full sweep.

## 1) Prepare the server VPS

- Build the release binaries.
- Generate or install a persistent certificate whose SAN covers the DNS name or
  IP you will use as `SERVER_NAME`.
- Keep all eight server listeners running on ports `4433` through `4440`.

## 2) Prepare the runner VPS

- Build the release binaries.
- Copy the CA file used to sign the server certificate onto the runner VPS.
- Copy `ops/scheduled-benchmarks.env.example` to `/etc/tls-pq-bench/scheduled.env`
  and fill in:
  - `REPO_DIR`
  - `RUNNER_BIN`
  - `SERVER_HOST`
  - `SERVER_NAME`
  - `CA_CERT`

Generate the recurring and daily configs:

```bash
SCHEDULE_ENV_FILE=/etc/tls-pq-bench/scheduled.env \
    ./scripts/generate_remote_schedule_configs.sh
```

That writes:

- `benchmarks/remote-recurring.toml`
- `benchmarks/remote-full.toml`

## 3) Install the timers

Copy the sample units into `/etc/systemd/system/` and enable them:

```bash
sudo cp ops/systemd/tls-pq-bench-track.service /etc/systemd/system/
sudo cp ops/systemd/tls-pq-bench-track.timer /etc/systemd/system/
sudo cp ops/systemd/tls-pq-bench-full.service /etc/systemd/system/
sudo cp ops/systemd/tls-pq-bench-full.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tls-pq-bench-track.timer
sudo systemctl enable --now tls-pq-bench-full.timer
```

The default schedule is:

- tracking matrix every 4 hours
- full matrix daily at `02:30 UTC`

## Outputs

Each scheduled run creates:

- `results/scheduled/<profile>-<timestamp>.jsonl`
- `results/scheduled/<profile>-<timestamp>.meta`
- `.logs/scheduled/<profile>-<timestamp>.log`

The wrapper script uses `flock` to avoid overlapping runs of the same profile.
