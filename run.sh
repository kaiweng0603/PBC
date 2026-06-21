#!/bin/bash

# 1. 編譯原始碼
echo "正在編譯 BLS.c..."
gcc -o bls_demo BLS.c -lpbc -lgmp

# 2. 檢查編譯是否成功，成功就直接執行
if [ $? -eq 0 ]; then
    echo "編譯成功，執行程式："
    echo "----------------------------------------"
    ./bls_demo
    echo "----------------------------------------"
else
    echo "錯誤：編譯失敗。請確認系統是否已安裝 gmp 與 pbc 函式庫。"
fi