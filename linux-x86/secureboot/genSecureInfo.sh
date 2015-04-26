#!/bin/bash
# This file is used to creat secureinfo and encrypt image
SEC_KEY_DIR=./Key
SEC_TOOL_DIR=.
SAVE_FOLDER=./image
KERNEL_AES_KEY=${SEC_KEY_DIR}/AESboot.bin
IMAGE_PRIVATE_KEY=${SEC_KEY_DIR}/RSAimage_priv.txt
IMAGE_PUBLIC_KEY=${SEC_KEY_DIR}/RSAimage_pub.txt
IMAGE_PUBLIC_KEY_BIN=${SEC_KEY_DIR}/RSAimage_pub.bin
FAKE_KEYSET=${SEC_KEY_DIR}/FakekeySet.bin
#512*4096=2097152
BLOCK_SIZE=2097152
${SEC_TOOL_DIR}/alignment.exe ${SAVE_FOLDER}/recovery.img
${SEC_TOOL_DIR}/SubSecureInfoGen.exe ${SAVE_FOLDER}/secure_info_recovery.bin ${SAVE_FOLDER}/recovery.img ${IMAGE_PRIVATE_KEY} ${IMAGE_PUBLIC_KEY} 0  8 1 ${BLOCK_SIZE} 0 ${SEC_TOOL_DIR}
${SEC_TOOL_DIR}/aescrypt2.exe 0 ${SAVE_FOLDER}/recovery.img ${SAVE_FOLDER}/recovery.img.aes ${KERNEL_AES_KEY}

${SEC_TOOL_DIR}/alignment.exe ${SAVE_FOLDER}/boot.img
${SEC_TOOL_DIR}/SubSecureInfoGen.exe ${SAVE_FOLDER}/secure_info_boot.bin ${SAVE_FOLDER}/boot.img ${IMAGE_PRIVATE_KEY} ${IMAGE_PUBLIC_KEY} 0  8 1 ${BLOCK_SIZE} 0 ${SEC_TOOL_DIR}
${SEC_TOOL_DIR}/aescrypt2.exe 0 ${SAVE_FOLDER}/boot.img ${SAVE_FOLDER}/boot.img.aes ${KERNEL_AES_KEY}
