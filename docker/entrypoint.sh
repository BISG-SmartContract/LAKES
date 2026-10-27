#!/usr/bin/env bash
set -euo pipefail

# One entrypoint serves the runtime daemon and standalone/external workers.
start_runtime() {
  # This is the only container allowed to mount the persistent Docker data volume.
  # A small socket volume connects independently supervised worker containers.
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    # Delegate controllers only inside this runtime's private cgroup namespace.
    if ! grep -qx '0::/' /proc/self/cgroup; then
      echo "[error] shared runtime requires --cgroupns=private on cgroup v2." >&2
      exit 1
    fi
    mkdir -p /sys/fs/cgroup/lakes-init
    ready=false
    for _ in $(seq 1 50); do
      # A short-lived process may disappear before its cgroup is updated.
      for process in $(cat /sys/fs/cgroup/cgroup.procs); do
        printf '%s\n' "$process" 2>/dev/null > /sys/fs/cgroup/lakes-init/cgroup.procs || true
      done
      if { sed -e 's/ / +/g' -e 's/^/+/' /sys/fs/cgroup/cgroup.controllers \
            > /sys/fs/cgroup/cgroup.subtree_control; } 2>/dev/null; then
        ready=true
        break
      fi
      sleep 0.02
    done
    if [ "$ready" != true ]; then
      echo "[error] cannot enable nested cgroup v2 controllers for shared runtime." >&2
      exit 1
    fi
  fi
  mkdir -p /run/lakes-runtime
  # An unclean container restart retains its writable layer, including this PID
  # file. PID numbers can be reused by this entrypoint in the new PID namespace.
  if [ -s /run/docker.pid ]; then
    previous_pid=$(cat /run/docker.pid)
    if [ "$previous_pid" != "$$" ] && kill -0 "$previous_pid" 2>/dev/null; then
      echo "[error] a Docker daemon is already running in this runtime container." >&2
      exit 1
    fi
    rm -f /run/docker.pid
  fi
  # Docker's managed-containerd supervisor otherwise mistakes a reused PID for
  # the old containerd after SIGKILL and waits on its stale Unix socket.
  if [ -s /run/docker/containerd/containerd.pid ]; then
    containerd_pid=$(cat /run/docker/containerd/containerd.pid)
    containerd_executable=$(readlink "/proc/$containerd_pid/exe" 2>/dev/null || true)
    case "$containerd_executable" in
      */containerd) ;;
      *) rm -f /run/docker/containerd/containerd.pid ;;
    esac
  fi
  exec dockerd \
    --host=unix:///run/lakes-runtime/docker.sock \
    --iptables=false --bridge=none --ip-forward=false --ip-masq=false "$@"
}

if [ "${1:-}" = "runtime" ]; then
  if [ "${LAKES_DOCKER_MODE:-auto}" != "auto" ]; then
    echo "[error] runtime command requires LAKES_DOCKER_MODE=auto; external mode is for workers." >&2
    exit 2
  fi
  shift
  start_runtime "$@"
fi

case "${LAKES_DOCKER_MODE:-auto}" in
external)
  # The scheduler owns the daemon. Never silently create another daemon when
  # its socket is unavailable, and validate the shared workspace before work.
  if ! python -m toolrank.docker_runtime check; then
    echo "[error] external Docker runtime is unavailable; refusing to start local dockerd." >&2
    exit 1
  fi
  ;;
auto)
  # Backward-compatible Docker-in-Docker for standalone invocations.
  if ! docker info >/dev/null 2>&1; then
    dockerd --iptables=false --bridge=none --ip-forward=false --ip-masq=false >/var/log/dockerd.log 2>&1 &
    for _ in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
    if ! docker info >/dev/null 2>&1; then
      echo "[error] internal dockerd did not start; execution requires docker run --privileged." >&2
      echo "[error] recommendation-only flows can continue; dockerd log tail follows:" >&2
      tail -n 30 /var/log/dockerd.log >&2 2>/dev/null || true
    fi
  fi
  ;;
*)
  echo "[error] LAKES_DOCKER_MODE must be auto or external." >&2
  exit 2
  ;;
esac

exec lakes "$@"
