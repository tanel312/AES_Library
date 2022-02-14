// AES_Library.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "AES_Library.h"


/*--------------------------------------------------------------------------------
 Constants
--------------------------------------------------------------------------------*/
BYTE const NumberOfRounds[] = { 10, 12, 14 };

/*-------------------------------------------------------------------------------
  AES_ECBmodeCBCmodeEncrypt
  Electronic Code Book mode & Cipher Block Chaining mode, need for data padding since data is encrypted
  Inputs: Key, KeySize, Iv, dwBufsize
  Input/Output: Buffer
-------------------------------------------------------------------------------*/
void AES_ECBmodeCBCmodeEncrypt(BYTE* const Key, BYTE KeySize, BYTE* Buffer, DWORD dwBufsize, BYTE* Iv, short Mode)
{
    UINT round = 0;
    BYTE* roundkeys;
    BYTE sbox[256] = { 0x00 };
    BYTE xorvector[AES_BLOCKSIZE];
    UINT keysizeaswords;
    UINT numberofrounds;
    int i;
    int numberofblocks;

    numberofblocks = dwBufsize / AES_BLOCKSIZE;
    if (dwBufsize % AES_BLOCKSIZE != 0)
    {
        numberofblocks++;
    }

    AES_Initialize_SBox(sbox);

    keysizeaswords = KeySize / 4;
    i = keysizeaswords / 2 - 2;
    numberofrounds = NumberOfRounds[i];
    i = (numberofrounds + 1) * 16;
    roundkeys = (BYTE*)malloc(i);
    memset(roundkeys, 0, i);
    AES_ExpandRoundKeys(Key, keysizeaswords, numberofrounds, roundkeys, sbox);

    if (Mode == AES_MODECBC)
        memcpy(xorvector, Iv, AES_BLOCKSIZE); // not needed in ECB
    for (i = 0; i < numberofblocks; i++)
    {
        if (Mode == AES_MODECBC)
            AES_AddVector(Buffer, xorvector, AES_BLOCKSIZE);
        AES_AddRoundKey(0, roundkeys, Buffer);
        for (round = 1; round <= numberofrounds; round++)
        {
            AES_SubstituteBytes(Buffer, sbox);
            AES_ShiftRows(Buffer, ENCRYPT);
            if (round < numberofrounds) // Mix Columns is not in last round 
                AES_MixColumns(Buffer, ENCRYPT);
            AES_AddRoundKey(round, roundkeys, Buffer);
        }
        if (Mode == AES_MODECBC)
            memcpy(xorvector, Buffer, AES_BLOCKSIZE);
        Buffer += AES_BLOCKSIZE;
    }
    free(roundkeys);
}

/*-------------------------------------------------------------------------------
  AES_ECBmodeCBCmodeDecrypt
  Electronic Code Book mode & Cipher Block Chaining mode, need for data padding since data is decrypted
  Inputs: Key, KeySize, Iv, dwBufsize
  Input/Output: Buffer
-------------------------------------------------------------------------------*/
void AES_ECBmodeCBCmodeDecrypt(BYTE* const Key, BYTE KeySize, BYTE* Buffer, DWORD dwBufsize, BYTE* Iv, short Mode)
{
    INT32 round = 0;
    BYTE* roundkeys;
    BYTE sbox[256] = { 0x00 };
    BYTE xorvector[AES_BLOCKSIZE];
    BYTE tmp[AES_BLOCKSIZE];
    UINT keysizeaswords;
    UINT numberofrounds;
    int i;
    int numberofblocks;

    numberofblocks = dwBufsize / AES_BLOCKSIZE;
    if (dwBufsize % AES_BLOCKSIZE != 0)
    {
        numberofblocks++;
    }

    AES_Initialize_SBox(sbox);

    keysizeaswords = KeySize / 4;
    i = keysizeaswords / 2 - 2;
    numberofrounds = NumberOfRounds[i];
    i = (numberofrounds + 1) * 16;
    roundkeys = (BYTE*)malloc(i);
    memset(roundkeys, 0, i);

    AES_ExpandRoundKeys(Key, keysizeaswords, numberofrounds, roundkeys, sbox);
    AES_Inverse_SBox(sbox);

    if (Mode == AES_MODECBC)
        memcpy(xorvector, Iv, AES_BLOCKSIZE);
    for (i = 0; i < numberofblocks; i++)
    {
        memcpy(tmp, Buffer, AES_BLOCKSIZE);
        AES_AddRoundKey(numberofrounds, roundkeys, Buffer);
        for (round = (numberofrounds - 1); round >= 0; round--)
        {
            AES_ShiftRows(Buffer, DECRYPT);
            AES_SubstituteBytes(Buffer, sbox);
            AES_AddRoundKey(round, roundkeys, Buffer);
            if (round > 0) // Mix Column is not in last round
                AES_MixColumns(Buffer, DECRYPT);
        }
        if (Mode == AES_MODECBC)
            AES_AddVector(Buffer, xorvector, AES_BLOCKSIZE);
        if (Mode == AES_MODECBC)
            memcpy(xorvector, tmp, AES_BLOCKSIZE);
        Buffer += AES_BLOCKSIZE;
    }
    free(roundkeys);
}

/*-------------------------------------------------------------------------------
  AES_CTRmodeOFBmodeEncryptDecrypt
  Counter mode & Output Feed Back mode, no need for data padding since vector is encrypted
  Inputs: Key, KeySize, InitCtr, dwBufsize
  Input/Output: Buffer
-------------------------------------------------------------------------------*/
void AES_CTRmodeOFBmodeEncryptDecrypt(BYTE* const Key, BYTE KeySize, BYTE* Buffer, DWORD dwBufsize, BYTE* InitCtr, short Mode)
{
    UINT round = 0;
    BYTE* roundkeys;
    BYTE sbox[256] = { 0x00 };
    BYTE counter[AES_BLOCKSIZE];
    BYTE plaincounter[AES_BLOCKSIZE];
    UINT keysizeaswords;
    UINT numberofrounds;
    int i;
    int blocksize = AES_BLOCKSIZE;
    int lastblocknumber;

    lastblocknumber = dwBufsize / AES_BLOCKSIZE;
    if (dwBufsize % AES_BLOCKSIZE == 0)
    {
        lastblocknumber--;
    }

    AES_Initialize_SBox(sbox);

    //Generate Round Keys
    keysizeaswords = KeySize / 4;
    i = keysizeaswords / 2 - 2;
    numberofrounds = NumberOfRounds[i];
    i = (numberofrounds + 1) * 16;
    roundkeys = (BYTE*)malloc(i);
    memset(roundkeys, 0, i);
    AES_ExpandRoundKeys(Key, keysizeaswords, numberofrounds, roundkeys, sbox);

    // transfer initial counter value to internal counter
    memcpy(plaincounter, InitCtr, AES_BLOCKSIZE);

    for (i = 0; i < lastblocknumber; i++)
    {
        memcpy(counter, plaincounter, AES_BLOCKSIZE);
        // encrypt counter value
        AES_AddRoundKey(0, roundkeys, counter);
        for (round = 1; round <= numberofrounds; round++)
        {
            AES_SubstituteBytes(counter, sbox);
            AES_ShiftRows(counter, ENCRYPT);
            if (round < numberofrounds) // Mix Columns is not in last round 
                AES_MixColumns(counter, ENCRYPT);
            AES_AddRoundKey(round, roundkeys, counter);
        }
        // end of counter encryption

        if (i == lastblocknumber) // last block could be smaller because of no padding
            blocksize = dwBufsize - (i * AES_BLOCKSIZE);
        // XOR input with encrypted counter
        AES_AddVector(Buffer, counter, blocksize);
        Buffer += AES_BLOCKSIZE;

        if (Mode == AES_MODECTR)
        {
            // increment counter value by 1
            int carry = 1;
            for (int j = (AES_BLOCKSIZE - 1); j >= 0; j--)
            {
                if (carry == 1)
                {
                    plaincounter[j] += 1;
                    if (plaincounter[j] == 0)
                        carry = 1;
                    else
                        carry = 0;
                }
            }
        }
        if (Mode == AES_MODEOFB)
            memcpy(plaincounter, counter, AES_BLOCKSIZE);
    }
    free(roundkeys);
}
/*-------------------------------------------------------------------------------
  AES_CFBmodeEncryptDecrypt
  Cipher Feed Back mode, no need for data padding since vector is encrypted
  Inputs: Key, KeySize, Iv, dwBufsize
  Input/Output: Buffer
-------------------------------------------------------------------------------*/
void AES_CFBmodeEncryptDecrypt(BYTE* const Key, BYTE KeySize, BYTE* Buffer, DWORD dwBufsize, BYTE* Iv, short Mode)
{
    UINT round = 0;
    BYTE* roundkeys;
    BYTE sbox[256] = { 0x00 };
    BYTE xorvector[AES_BLOCKSIZE];
    BYTE tmpbuf[AES_BLOCKSIZE];
    UINT keysizeaswords;
    UINT numberofrounds;
    int i;
    int blocksize = AES_BLOCKSIZE;
    int lastblocknumber;

    lastblocknumber = dwBufsize / AES_BLOCKSIZE;
    if (dwBufsize % AES_BLOCKSIZE == 0)
    {
        lastblocknumber--;
    }

    AES_Initialize_SBox(sbox);

    //Generate Round Keys
    keysizeaswords = KeySize / 4;
    i = keysizeaswords / 2 - 2;
    numberofrounds = NumberOfRounds[i];
    i = (numberofrounds + 1) * 16;
    roundkeys = (BYTE*)malloc(i);
    memset(roundkeys, 0, i);
    AES_ExpandRoundKeys(Key, keysizeaswords, numberofrounds, roundkeys, sbox);

    // transfer initial value to internal vector
    memcpy(xorvector, Iv, AES_BLOCKSIZE);

    for (i = 0; i <= lastblocknumber; i++)
    {
        // encrypt vector value
        AES_AddRoundKey(0, roundkeys, xorvector);
        for (round = 1; round <= numberofrounds; round++)
        {
            AES_SubstituteBytes(xorvector, sbox);
            AES_ShiftRows(xorvector, ENCRYPT);
            if (round < numberofrounds) // Mix Columns is not in last round 
                AES_MixColumns(xorvector, ENCRYPT);
            AES_AddRoundKey(round, roundkeys, xorvector);
        }
        // end of vector encryption

        // get copy of cyphered block for decrytion
        if (Mode == DECRYPT)
            memcpy(tmpbuf, Buffer, AES_BLOCKSIZE);
        if (i == lastblocknumber) // last block could be smaller because of no padding
            blocksize = dwBufsize - (i * AES_BLOCKSIZE);
        // XOR input with encrypted counter
        AES_AddVector(Buffer, xorvector, blocksize);
        // crypted input block will be used for next iteration
        if (Mode == DECRYPT)
            memcpy(xorvector, tmpbuf, AES_BLOCKSIZE);
        else
            memcpy(xorvector, Buffer, AES_BLOCKSIZE);
        // move data buffer pointer 1 block further
        Buffer += AES_BLOCKSIZE;
    }
    free(roundkeys);
}
