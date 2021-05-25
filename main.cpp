#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"


int main() {
    std::cout << "=============================" << std::endl;
    std::cout << "Please enter 1 for encrypt --or-- enter 2 for decrypt enc.aes content" << std::endl;
    std::cout << "=============================" << std::endl;
    std::cout << "==============1 Or 2============" << std::endl;
    char encOrDecInput[2];
    std::cin.getline(encOrDecInput, sizeof(encOrDecInput));

    if(encOrDecInput[0] == '1'){
        std::cout << "=============================" << std::endl;
        std::cout << " 128-bit AES Encryption Tool   " << std::endl;
        std::cout << "=============================" << std::endl;

        char message[1024];

        std::cout << "Enter the message to encrypt: ";
        std::cin.getline(message, sizeof(message));
        std::cout << message << std::endl;

        // Pad message to 16 bytes
        int originalLen = strlen((const char *)message);

        int paddedMessageLen = originalLen;

        if ((paddedMessageLen % 16) != 0) {
            paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
        }

        unsigned char * paddedMessage = new unsigned char[paddedMessageLen];
        for (int i = 0; i < paddedMessageLen; i++) {
            if (i >= originalLen) {
                paddedMessage[i] = 0;
            }
            else {
                paddedMessage[i] = message[i];
            }
        }

        unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];

        std::string str;
        std::ifstream infile;
        infile.open("keyfile", std::ios::in | std::ios::binary);

        if (infile.is_open())
        {
            getline(infile, str); // The first line of file should be the key
            infile.close();
        }

        else std::cout << "Unable to open file";

        std::istringstream hex_chars_stream(str);
        unsigned char key[16];
        int i = 0;
        unsigned int c;
        while (hex_chars_stream >> std::hex >> c)
        {
            key[i] = c;
            i++;
        }

        unsigned char expandedKey[176];

        KeyExpansion(key, expandedKey);

        for (int i = 0; i < paddedMessageLen; i += 16) {
            AESEncrypt(paddedMessage+i, expandedKey, encryptedMessage+i);
        }

        std::cout << "Encrypted message in hex:" << std::endl;
        for (int i = 0; i < paddedMessageLen; i++) {
            std::cout << std::hex << (int) encryptedMessage[i];
            std::cout << " ";
        }

        std::cout << std::endl;

        // Write the encrypted string out to file "message.txt"
        std::ofstream outfile;
        outfile.open("enc.aes", std::ios::out | std::ios::binary);
        if (outfile.is_open())
        {
            outfile << encryptedMessage;
            outfile.close();
            std::cout << "Wrote encrypted message to file enc.aes" << std::endl;
        }

        else std::cout << "Unable to open file";

        // Free memory
        delete[] paddedMessage;
        delete[] encryptedMessage;
    }
    else{
        std::cout << "=============================" << std::endl;
        std::cout << " 128-bit AES Decryption Tool " << std::endl;
        std::cout << "=============================" << std::endl;

        // Read in the message from message.aes
        std::string msgstr;
        std::ifstream infile;
        infile.open("enc.aes", std::ios::in | std::ios::binary);

        if (infile.is_open())
        {
            getline(infile, msgstr); // The first line of file is the message
            std::cout << "Read in encrypted message from enc.aes" << std::endl;
            infile.close();
        }
        else
            std::cout << "Unable to open file";

        char * msg = new char[msgstr.size()+1];

        strcpy(msg, msgstr.c_str());

        int n = strlen((const char*)msg);

        unsigned char * encryptedMessage = new unsigned char[n];
        for (int i = 0; i < n; i++) {
            encryptedMessage[i] = (unsigned char)msg[i];
        }

        // Free memory
        delete[] msg;

        // Read in the key
        std::string keystr;
        std::ifstream keyfile;
        keyfile.open("keyfile", std::ios::in | std::ios::binary);

        if (keyfile.is_open())
        {
            getline(keyfile, keystr); // The first line of file should be the key
            std::cout << "Read in the 128-bit key from keyfile" << std::endl;
            keyfile.close();
        }

        else
            std::cout << "Unable to open file";

        std::istringstream hex_chars_stream(keystr);
        unsigned char key[16];
        int i = 0;
        unsigned int c;
        while (hex_chars_stream >> std::hex >> c)
        {
            key[i] = c;
            i++;
        }

        unsigned char expandedKey[176];

        KeyExpansion(key, expandedKey);

        int messageLen = strlen((const char *)encryptedMessage);

        unsigned char * decryptedMessage = new unsigned char[messageLen];

        for (int i = 0; i < messageLen; i += 16) {
            AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
        }

        std::cout << "Decrypted message in hex:" << std::endl;
        for (int i = 0; i < messageLen; i++) {
            std::cout << std::hex << (int)decryptedMessage[i];
            std::cout << " ";
        }
        std::cout << std::endl;
        std::cout << "Decrypted message: ";
        for (int i = 0; i < strlen((const char *)decryptedMessage); i++) {
            std::cout << decryptedMessage[i];
        }
        std::cout << std::endl;
    }




    return 0;
}


/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table
 */
void SubBytes(unsigned char * state) {
    for (int i = 0; i < 16; i++) {
        state[i] = s[state[i]];
    }
}

// Shift left, adds diffusion
void ShiftRows(unsigned char * state) {
    unsigned char tmp[16];

    /* Column 1 */
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    /* Column 2 */
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    /* Column 3 */
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    /* Column 4 */
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/* MixColumns uses mul2, mul3 look-up tables
 * Source of diffusion
 */
void MixColumns(unsigned char * state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESEncrypt()
 */
void Round(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

// Same as Round() except it doesn't mix columns
void FinalRound(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
    unsigned char state[16]; // Stores the first 16 bytes of original message

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

    int numberOfRounds = 9;

    AddRoundKey(state, expandedKey); // Initial round

    for (int i = 0; i < numberOfRounds; i++) {
        Round(state, expandedKey + (16 * (i+1)));
    }

    FinalRound(state, expandedKey + 160);

    // Copy encrypted state to buffer
    for (int i = 0; i < 16; i++) {
        encryptedMessage[i] = state[i];
    }
}

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 * So basically does the same as AddRoundKey in the encryption
 */
void SubRoundKey(unsigned char * state, unsigned char * roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}


/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
void InverseMixColumns(unsigned char * state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}


// Shifts rows right (rather than left) for decryption
void ShiftRowsDec(unsigned char * state) {
    unsigned char tmp[16];

    /* Column 1 */
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    /* Column 2 */
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];

    /* Column 3 */
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    /* Column 4 */
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
void SubBytesDec(unsigned char * state) {
    for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
        state[i] = inv_s[state[i]];
    }
}


/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
void RoundDec(unsigned char * state, unsigned char * key) {
    SubRoundKey(state, key);
    InverseMixColumns(state);
    ShiftRowsDec(state);
    SubBytesDec(state);
}

// Same as Round() but no InverseMixColumns
void InitialRound(unsigned char * state, unsigned char * key) {
    SubRoundKey(state, key);
    ShiftRowsDec(state);
    SubBytesDec(state);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
void AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage)
{
    unsigned char state[16]; // Stores the first 16 bytes of encrypted message

    for (int i = 0; i < 16; i++) {
        state[i] = encryptedMessage[i];
    }

    InitialRound(state, expandedKey+160);

    int numberOfRounds = 9;

    for (int i = 8; i >= 0; i--) {
        RoundDec(state, expandedKey + (16 * (i + 1)));
    }

    SubRoundKey(state, expandedKey); // Final round

    // Copy decrypted state to buffer
    for (int i = 0; i < 16; i++) {
        decryptedMessage[i] = state[i];
    }
}