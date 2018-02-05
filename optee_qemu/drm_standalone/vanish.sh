#!/usr/bin/env bash


SECTION=".secure_code"
objcopy="arm-none-eabi-objcopy"

$objcopy -j .secure_code -O binary $1 sec.bin


# modify/encrypt the section here

python encrypt.py sec.bin sec.enc


# reinsert section

$objcopy --update-section .secure_code=sec.enc $1 hello_blob_enc

rm -f sec.bin
