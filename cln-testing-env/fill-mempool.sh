#!/bin/bash

# Bitcoin CLI command
BTC_CLI="bitcoin-cli -signet -rpcpassword=bitcoin -rpcuser=bitcoin"

# Function to get current wallet balance
get_balance() {
    $BTC_CLI getbalance
}

# Function to get a new address from the wallet
get_new_address() {
    $BTC_CLI getnewaddress
}

# Small amount to send (in BTC)
AMOUNT=0.000003000

# Main loop
while true; do
    sleep 0.5
    # Get current balance
    BALANCE=$(get_balance)

    # Check if balance is too low to continue
    if (( $(echo "$BALANCE < $AMOUNT" | bc -l) )); then
        echo "Balance too low to continue: $BALANCE BTC"
        continue
    fi

    # Get a new address
    ADDRESS=$(get_new_address)

    # Send transaction
    echo "Sending $AMOUNT BTC to $ADDRESS. Current balance: $BALANCE BTC"
    TXID=$($BTC_CLI sendtoaddress "$ADDRESS" "$AMOUNT")

    if [ $? -eq 0 ]; then
        echo "Transaction sent: $TXID"
    else
        echo "Transaction failed"
        continue
    fi

    # Small delay to prevent overwhelming the node
done

echo "Script finished"
