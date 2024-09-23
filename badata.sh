#!/bin/sh

# generate board.dtb
generate_dtb() {

    GENPP_SYMMETRIC_KEY_0=keys/key_0.bin \
    GENPP_SYMMETRIC_IV_0=keys/iv_0.bin \
    GENPP_SYMMETRIC_KEY_1=keys/key_1.bin \
    GENPP_SYMMETRIC_IV_1=keys/iv_1.bin \
    GENPP_KEY_NAME_0=key-name-0 \
    GENPP_KEY_NAME_1=key-name-1 \
    GENPP_SIGNING_ALGO_16=SHA256_PSS \
    GENPP_PRIVKEY_16=keys/private_key_0.pem \
    GENPP_PRIVKEY_PASSWORD_16=test \
    GENPP_SIGNATURE_NODE_NAME_16=Signature \
    GENPP_SIGNING_ALGO_17=SHA256_PSS \
    GENPP_PRIVKEY_17=keys/private_key_1.pem \
    GENPP_PRIVKEY_PASSWORD_17=test \
    GENPP_SIGNATURE_NODE_NAME_17=Signature_1 \
    python3 genpp.py board.dtb board.dts $1 $2

}

# Calculate the number of input parameters
input_arg="$#"

# Print the number of input parameters
# echo "Length of input agrument: $input_arg"

if [ $input_arg == 2 ]; then
# read the mfg data
    readmfg $1 $2
elif [ $input_arg == 3 ]; then
# write the mfg data
    generate_dtb $2 $3
    readmfg $1 $2
else
    echo 'invalid input' > /dev/console
fi
