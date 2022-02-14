// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"
#include "AES_Library.h"

/*-------------------------------------------------------------------------------
  AES_Functions

  Credits: 
  Kokkev(https://github.com/kokke), released into the public domain
  https://en.wikipedia.org/wiki/Rijndael_S-box
-------------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------------
  AES_AddVector
  Input: Iv
  Output: Output
-------------------------------------------------------------------------------*/
void AES_AddVector(BYTE* Output, BYTE* Iv, int Blocksize)
{
    for (int i = 0; i < Blocksize; i++)
    {
        Output[i] ^= Iv[i];
    }

}
/*-------------------------------------------------------------------------------
  AES_Initialize_SBox

  Output: Sbox
-------------------------------------------------------------------------------*/
void AES_Initialize_SBox(BYTE* Sbox)
{
    BYTE p = 1, q = 1;

    /* loop invariant: p * q == 1 in the Galois field */
    do {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* compute the affine transformation */
        Sbox[p] = (q ^
            ((q << 1) | (q >> 7)) ^
            ((q << 2) | (q >> 6)) ^
            ((q << 3) | (q >> 5)) ^
            ((q << 4) | (q >> 4))) ^ 0x63;
    } while (p != 1);
    Sbox[0] = 0x63; // special case
}
/*-------------------------------------------------------------------------------
  AES_Inverse_SBox
  Input/Output: Sbox
-------------------------------------------------------------------------------*/
void AES_Inverse_SBox(BYTE* Sbox)
{
    BYTE sbox[256];

    for (int i = 0; i < 256; i++)
        sbox[Sbox[i]] = i;
    memcpy(Sbox, sbox, sizeof(sbox));
}
/*-------------------------------------------------------------------------------
  AES_ExpandRoundKeys
  Input: Key, KeySizeInWords, NumberOfRounds, Sbox
  Output: RoundKey
-------------------------------------------------------------------------------*/
void AES_ExpandRoundKeys(BYTE const* Key, UINT KeySizeInWords, UINT NumberOfRounds, BYTE* RoundKey, BYTE* Sbox)
{
    UINT i, j;
    BYTE tmp[4];
    const BYTE RoundConstant[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    memcpy(RoundKey, Key, KeySizeInWords * 4);
    for (i = KeySizeInWords; i < 4 * (NumberOfRounds + 1); i++)
    {
        for (j = 0; j < 4; j++)
            tmp[j] = RoundKey[(i - 1) * 4 + j];

        if (i % KeySizeInWords == 0)
        {
            RotateLeft(tmp, 1, 1);
            for (j = 0; j < 4; j++)
                tmp[j] = Sbox[tmp[j]];
            tmp[0] = tmp[0] ^ RoundConstant[i / KeySizeInWords];
        }

        if (KeySizeInWords == 8) // AES256
        {
            if (4 == i % KeySizeInWords)
            {
                for (j = 0; j < 4; j++)
                    tmp[j] = Sbox[tmp[j]];
            }
        }
        for (j = 0; j < 4; j++)
            RoundKey[i * 4 + j] = RoundKey[(i - KeySizeInWords) * 4 + j] ^ tmp[j];
    }
}

/*-------------------------------------------------------------------------------
  AES_AddRoundKey
  Input: RoundNumber, RoundKey
  Input/Output: State
-------------------------------------------------------------------------------*/
void AES_AddRoundKey(UINT RoundNumber, BYTE* RoundKey, BYTE* State)
{
    BYTE  i;
    BYTE  j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            *(State + (i * 4) + j) ^= RoundKey[(RoundNumber * 4 * 4) + (i * 4) + j];
        }
    }
}

/*-------------------------------------------------------------------------------
  AES_SubstituteBytes
  Input: Sbox
  Input/Output: State
-------------------------------------------------------------------------------*/
void AES_SubstituteBytes(BYTE* State, BYTE* Sbox)
{
    UINT i;
    UINT j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            *(State + (j * 4 + i)) = Sbox[*(State + (j * 4 + i))];
        }
    }
}

/*-------------------------------------------------------------------------------
  RotateLeft
  Input: Cnt, Step
  Input/Output: Line
-------------------------------------------------------------------------------*/
void RotateLeft(BYTE* Line, BYTE Cnt, BYTE Step)
{
    BYTE z[4];
    for (int i = 0; i < 4; i++)
    {
        z[i] = *(Line + (3 - i) * Step);
    }
    UINT* t1 = (UINT*)z;
    UINT t2 = *t1;
    *t1 = t2 << Cnt * 8 | t2 >> (4 - Cnt) * 8;
    for (int i = 0; i < 4; i++)
    {
        *(Line + (3 - i) * Step) = z[i];
    }
}

/*-------------------------------------------------------------------------------
  AES_ShiftRows
  Input: Mode
  Input/Output: State
-------------------------------------------------------------------------------*/
void AES_ShiftRows(BYTE* State, BYTE Mode)
{
    if (Mode == ENCRYPT)
    {
        RotateLeft(State + 1, 1, 4);
        RotateLeft(State + 2, 2, 4);
        RotateLeft(State + 3, 3, 4);
    }
    else // DECRYPT
    {
        RotateLeft(State + 1, 3, 4);
        RotateLeft(State + 2, 2, 4);
        RotateLeft(State + 3, 1, 4);
    }
}

/*-------------------------------------------------------------------------------
  GaloisFieldMultiplication
  Inputs: Inp1, Inp2
  Output: (function return)
-------------------------------------------------------------------------------*/
BYTE GaloisFieldMultiplication(BYTE Inp1, BYTE Inp2)
{
    BYTE product = 0;
    while (Inp1 && Inp2)
    {
        if (Inp2 & 1) // Inp2 is odd
            product ^= Inp1;
        Inp1 = (Inp1 & 0x80) ? (Inp1 << 1) ^ 0x11b : (Inp1 <<= 1);
        Inp2 >>= 1;
    }
    return product;
}

/*-------------------------------------------------------------------------------
  AES_MixColumns
  Input: Mode
  Input/Output: State
-------------------------------------------------------------------------------*/
void AES_MixColumns(BYTE* State, BYTE Mode)
{
    BYTE M[2][16] =
    { { 02, 03, 01, 01, 01, 02, 03, 01, 01, 01, 02, 03, 03, 01, 01, 02 }, // Mix
    { 0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e } }; // inverse mix
    BYTE tmp[4];
    BYTE state[4][4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                tmp[k] = GaloisFieldMultiplication(M[Mode][j * 4 + k], *(State + (i * 4 + k)));
            }
            state[i][j] = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        }
    }
    memcpy(State, state, sizeof(state));
}

