#!/bin/bash

# Check for correct number of arguments
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <hex_number>"
    exit 1
fi

HEX_NUMBER=$1

# Remove the '0x' prefix if present
HEX_NUMBER=${HEX_NUMBER^^} # Convert to uppercase to ensure consistency
HEX_NUMBER=${HEX_NUMBER#0X} # Remove '0X' prefix if exists

# Convert hexadecimal num to decimal
DECIMAL_NUMBER=$(echo "ibase=16; $HEX_NUMBER" | bc)

# Print the decimal equivalent
echo "Decimal equivalent: $DECIMAL_NUMBER"