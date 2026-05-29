#!/bin/bash

TARGET=$1

echo "========================================="
echo " LabThinkTank Offensive Recon Pipeline"
echo "========================================="

mkdir -p reports/$TARGET

echo "[+] Running Nmap"
nmap -sC -sV $TARGET -oN reports/$TARGET/nmap.txt

echo "[+] Running WhatWeb"
whatweb http://$TARGET > reports/$TARGET/whatweb.txt

echo "[+] Running Dirsearch"
dirsearch -u http://$TARGET \
-o reports/$TARGET/dirsearch.txt

echo "[+] Recon Completed"
