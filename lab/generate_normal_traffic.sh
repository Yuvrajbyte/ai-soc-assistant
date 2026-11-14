#!/bin/bash
# Generates realistic, spaced-out SSH traffic against the lab victim.
# Run from Kali: bash generate_normal_traffic.sh

VICTIM="192.168.56.10"
USER="labuser"

for i in $(seq 1 20); do
    # Random delay between 15-45 seconds, mimicking real human gaps
    DELAY=$((RANDOM % 30 + 15))

    # Random harmless command each time, for variety in session content
    CMDS=("whoami" "date" "uptime" "ls" "pwd" "echo hello")
    CMD=${CMDS[$RANDOM % ${#CMDS[@]}]}

    echo "[$i/20] Running: $CMD (then waiting ${DELAY}s)"
    sshpass -p 'YOUR_PASSWORD_HERE' ssh -o StrictHostKeyChecking=no "$USER@$VICTIM" "$CMD"

    sleep "$DELAY"
done

echo "Done. Pull the updated auth.log from the victim now."