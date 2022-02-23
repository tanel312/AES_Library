# AES_Library
AES 128/192/256 encryption/decryption in modes: CBC, ECB, CTR, OFB &amp; CFB (a sample desktop application is given in https://github.com/tanel312/AES_LibExample)
As a blockcipher AES encrypts a block of data in a fixed size that is 128-bit (called blocksize; equals to 16 bytes). It means that AES can only encrypt multiple of the blocksize. If the data to be encrypted is not multiple of the blocksize, pad data needs to be added to match the block size. i.e. if the input data size is 14 bytes, it is smaller than a block and needs padding of 2 more bytes.

By definition AES is a blockcipher methodology but it can be used as a blockcipher or a stream cipher depending on the modes.

AES_Library supports encryption and decryption in five modes;
ECB: Electronic Code Book
CBC: Cypher Block Chaining
CTR: Counter
CFB: Cipher Feed Back
OFB: Output Feed Back

In the ECB and CBC modes of AES, the encryption algorithm is applied onto the input data. If the input data is much bigger than a block; 16 bytes. In this case, the input data is divided into blocks and is padded then encrypted block by block. i.e. if the input data size is 5821 bytes, it is 363 blocks and 13 bytes. It means that the input data size is not multiple of the block size and needs padding of 3 more bytes. When padding is done, the data size becomes 5824 bytes (364 blocks). For decryption, no padding is needed since the encrypted data should be multiple of the blocksize.

Input data padding and buffer size adjustment must be completed before calling “AES_ECBmodeCBCmodeEncrypt” and “AES_ECBmodeCBCmodeDecrypt” functions. 

where
Key: AES key
Keysize; sizeof key in bytes; 16 (AES-128bit), 24 (AES-192bit) or 32 (AES-256bit)
DataBuffer: Data buffer (input and output data)
dwBufsize: size of the data
Iv: Initial vector (16 bytes - 128bit)
Mode: Mode of AES; AES_MODEECB or AES_MODECBC

If input buffer is not aligned properly, memory corruption may occur.

In CTR, CFB and OFB modes, a vector (initial vector, counter or feedback) in the size of a block is encrypted. Input data is xor’ed with the vector to get encrypted output. Since the blockcypher is used as a stream cipher, the input data does not need to be multiple of the blocksize and padding is not needed.

“AES_CFBmodeEncryptDecrypt” and “AES_CTRmodeOFBmodeEncryptDecrypt” functions are directly called without any padding.

where
Key: AES key
Keysize; sizeof key in bytes; 16 (AES-128bit), 24 (AES-192bit) or 32 (AES-256bit)
DataBuffer: Data buffer (input and output data)
dwBufsize: size of the data
InitCtr: Initial Counter value (16 bytes - 128bit)
Mode: Mode of AES; AES_MODEECB or AES_MODECBC
Func: type of process; ENCRYPT or DECRYPT

It is is provided under GNU General Public License, as it is with no warranty or support. 
