#pragma once

#include "framework.h"

#define AES_KEYSIZE128        16
#define AES_KEYSIZE192        24
#define AES_KEYSIZE256        32
#define AES_BLOCKSIZE         16

#define AES_KEYASCII 1
#define AES_KEYHEX	2

#define ENCRYPT 0
#define DECRYPT 1

#define AES_MODEECB 0
#define AES_MODECBC 1
#define AES_MODECTR 2
#define AES_MODEOFB 3
#define AES_MODECFB 4

void AES_ECBmodeCBCmodeEncrypt(BYTE* const key, BYTE keysize, BYTE* DataBuffer, DWORD dwBufsize, BYTE* Iv, short Mode);
void AES_ECBmodeCBCmodeDecrypt(BYTE* const key, BYTE keysize, BYTE* DataBuffer, DWORD dwBufsize, BYTE* Iv, short Mode);
void AES_CFBmodeEncryptDecrypt(BYTE* const Key, BYTE KeySize, BYTE* DataBuffer, DWORD dwBufsize, BYTE* InitCtr, short Func);
void AES_CTRmodeOFBmodeEncryptDecrypt(BYTE* const Key, BYTE KeySize, BYTE* DataBuffer, DWORD dwBufsize, BYTE* InitCtr, short Mode);
