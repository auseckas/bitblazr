#!/bin/bash
log_level=$1
sensor_name=$2

mount -t tracefs tracefs /sys/kernel/tracing/
if ! grep -qs 'tracefs' /proc/mounts; then
    echo 'Could not mount in tracefs. This could impact functionality. Please make sure the container was started with --privileged flag.'
fi

mount -t securityfs securityfs /sys/kernel/security
if ! grep -qs 'securityfs' /proc/mounts; then
    echo "Could not mount in securityfs. This could will impact LSM functionality. Please make sure the container was started with --privileged flag."
fi

CONFIG_DIR=/app/config RUST_LOG=$log_level /app/bitblazr --name=$sensor_name
