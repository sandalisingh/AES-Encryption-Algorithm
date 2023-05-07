#include "AES.h"

AES::AES(AESKeyLength keyLength) {
  this->NoOfCols = 4;
  switch (keyLength) {
    case AESKeyLength::AES_128:
      this->NoOfWordsInKey = 4;
      this->NoOfRounds = 10;
      break;
    case AESKeyLength::AES_192:
      this->NoOfWordsInKey = 6;
      this->NoOfRounds = 12;
      break;
    case AESKeyLength::AES_256:
      this->NoOfWordsInKey = 8;
      this->NoOfRounds = 14;
      break;
  }

  blockBytesLen = 4 * this->NoOfCols * sizeof(unsigned char);
}

unsigned char *AES::ENCRYPTION(unsigned char PlainText[], unsigned int PlainText_Lt, unsigned char CypherKey[]) {
  CheckLength(PlainText_Lt);  //check length of plaintext

  unsigned char *OUTPUT = new unsigned char[PlainText_Lt];
  unsigned char *RoundKeys = new unsigned char[4 * NoOfCols * (NoOfRounds + 1)];

  KeyExpansion(CypherKey, RoundKeys);   // to produce round keys

  for (unsigned int i = 0; i < PlainText_Lt; i += blockBytesLen) {
    EncryptBlock(PlainText + i, OUTPUT + i, RoundKeys);
  }

  delete[] RoundKeys;

  return OUTPUT;
}

unsigned char *AES::DECRYPTION(unsigned char PlainText[], unsigned int PlainText_Lt, unsigned char CypherKey[]) {
  CheckLength(PlainText_Lt);
  unsigned char *OUTPUT = new unsigned char[PlainText_Lt];
  unsigned char *RoundKeys = new unsigned char[4 * NoOfCols * (NoOfRounds + 1)];
  KeyExpansion(CypherKey, RoundKeys);
  for (unsigned int i = 0; i < PlainText_Lt; i += blockBytesLen) {
    DecryptBlock(PlainText + i, OUTPUT + i, RoundKeys);
  }

  delete[] RoundKeys;

  return OUTPUT;
}

void AES::CheckLength(unsigned int len) { // to check the length of plaintext
  if (len % blockBytesLen != 0) {
    throw std::length_error("Plaintext length must be divisible by " + blockBytesLen);
  }
}

void AES::EncryptBlock(unsigned char PlainText[], unsigned char OUTPUT[], unsigned char *RoundKeys) {
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned char[4 * NoOfCols];
  int i, j, round;
  for (i = 0; i < 4; i++) {
    state[i] = state[0] + NoOfCols * i;
  }

  //------------------- COPYING PLAINTEXT TO INPUT MATRIX -----------------------

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      state[i][j] = PlainText[i + 4 * j];
    }
  }

  //------------------- 0th ROUND - 1 operation -----------------------

  AddRoundKey(state, RoundKeys);

  //------------------- 1 to 2nd LAST ROUND - 4 operations -----------------------

  for (round = 1; round <= NoOfRounds - 1; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, RoundKeys + round * 4 * NoOfCols);
  }

  //------------------- LAST ROUND - 3 OPERATIONS -----------------------

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, RoundKeys + NoOfRounds * 4 * NoOfCols);

  //------------------- COPYING STATE TO OUTPUT MATRIX -----------------------

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      OUTPUT[i + 4 * j] = state[i][j];
    }
  }

  //------------------- FREE UP SPACE -----------------------

  delete[] state[0];
  delete[] state;
}

void AES::DecryptBlock(unsigned char PlainText[], unsigned char OUTPUT[], unsigned char *RoundKeys) {
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned char[4 * NoOfCols];
  int i, j, round;
  for (i = 0; i < 4; i++) {
    state[i] = state[0] + NoOfCols * i;
  }

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      state[i][j] = PlainText[i + 4 * j];
    }
  }

  AddRoundKey(state, RoundKeys + NoOfRounds * 4 * NoOfCols);

  for (round = NoOfRounds - 1; round >= 1; round--) {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, RoundKeys + round * 4 * NoOfCols);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, RoundKeys);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      OUTPUT[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

void AES::SubBytes(unsigned char **state) {
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      t = state[i][j];
      state[i][j] = S_BOX[t / 16][t % 16];
    }
  }
}

void AES::ShiftRow(unsigned char **state, int i, int n)  // shift row i on n positions
{
  unsigned char *tmp = new unsigned char[NoOfCols];
  for (int j = 0; j < NoOfCols; j++) {
    tmp[j] = state[i][(j + n) % NoOfCols];
  }
  memcpy(state[i], tmp, NoOfCols * sizeof(unsigned char));

  delete[] tmp;
}

void AES::ShiftRows(unsigned char **state) {
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)  // multiply on x
{
  return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns(unsigned char **state) {
  unsigned char temp_state[4][4];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        if (CMDS[i][k] == 1)
          temp_state[i][j] ^= state[k][j];
        else
          temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
}

void AES::AddRoundKey(unsigned char **state, unsigned char *CypherKey) {
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      state[i][j] = state[i][j] ^ CypherKey[i + 4 * j];
    }
  }
}

void AES::XorBlocks(unsigned char *a, unsigned char *b, unsigned char *c, unsigned int len) {
  for (unsigned int i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}

//------------------->> KEY EXPANSION & ITS SUB FUNCTIONS <<-----------------------

void AES::SubWord(unsigned char *a) {   // SUBSITUTION USING S-BOX
  int i;
  for (i = 0; i < 4; i++) {
    a[i] = S_BOX[a[i] / 16][a[i] % 16];
  }
}

void AES::RotWord(unsigned char *a) {    // ROTATING BYTES OF A 4-BYTE WORD
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XORing_words(unsigned char *a, unsigned char *b, unsigned char *c) {   
  int i;
  for (i = 0; i < 4; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char *a, int n) {
  int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++) {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char CypherKey[], unsigned char w[]) {
  unsigned char *temp = new unsigned char[4];
  unsigned char *rcon = new unsigned char[4];

  int i = 0;

  //------------------- THE FIRST 4 WORDS-----------------------
  while (i < 4 * NoOfWordsInKey) {
    w[i] = CypherKey[i];
    i++;
  }

  i = 4 * NoOfWordsInKey;

  //------------------- THE REST OF THE WORDS-----------------------
  while (i < 4 * NoOfCols * (NoOfRounds + 1)) {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    //------------------- DIVISIBLE BY 4-----------------------
    if (i / 4 % NoOfWordsInKey == 0) {
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, i / (NoOfWordsInKey * 4));
      XORing_words(temp, rcon, temp);
    } 
    
    //------------------- NOT DIVISBLE BY 4-----------------------
    else if (NoOfWordsInKey > 6 && i / 4 % NoOfWordsInKey == 4) {
      SubWord(temp);
    }

    //------------------- ASSIGNING VALUE TO THE WORDS-----------------------
    w[i + 0] = w[i - 4 * NoOfWordsInKey] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * NoOfWordsInKey] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * NoOfWordsInKey] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * NoOfWordsInKey] ^ temp[3];
    i += 4;
  }

  //------------------- FREE UP SPACE-----------------------
  delete[] rcon;
  delete[] temp;
}

//------------------->> DECRYPTON <<-----------------------

void AES::InvSubBytes(unsigned char **state) {
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < NoOfCols; j++) {
      t = state[i][j];
      state[i][j] = Inverse_S_BOX[t / 16][t % 16];
    }
  }
}

void AES::InvMixColumns(unsigned char **state) {
  unsigned char temp_state[4][4];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
}

void AES::InvShiftRows(unsigned char **state) {
  ShiftRow(state, 1, NoOfCols - 1);
  ShiftRow(state, 2, NoOfCols - 2);
  ShiftRow(state, 3, NoOfCols - 3);
}

//------------------->> DISPLAY FUNCTIONS <<-----------------------

void AES::Display_HEX_Array(unsigned char a[], unsigned int n) {
  for (unsigned int i = 0; i < n; i++) {
    printf("%02x ", a[i]);
  }
}

void AES::Display_HEX_Vector(std::vector<unsigned char> a) {
  for (unsigned int i = 0; i < a.size(); i++) {
    printf("%02x ", a[i]);
  }
}

//------------------->> ARRAy <-> VECTOR <<-----------------------

std::vector<unsigned char> AES::ArrayToVector(unsigned char *a, unsigned int len) {
  std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
  return v;
}

unsigned char *AES::VectorToArray(std::vector<unsigned char> a) {
  return a.data();    // vector.data --> returns pointer to the array
}

std::vector<unsigned char> AES::ENCRYPTION(std::vector<unsigned char> PlainText, std::vector<unsigned char> CypherKey) {
  unsigned char *OUTPUT = ENCRYPTION(VectorToArray(PlainText), (unsigned int)PlainText.size(), VectorToArray(CypherKey));
  std::vector<unsigned char> v = ArrayToVector(OUTPUT, PlainText.size());
  delete[] OUTPUT;
  return v;
}

std::vector<unsigned char> AES::DECRYPTION(std::vector<unsigned char> PlainText, std::vector<unsigned char> CypherKey) {
  unsigned char *OUTPUT = DECRYPTION(VectorToArray(PlainText), (unsigned int)PlainText.size(), VectorToArray(CypherKey));
  std::vector<unsigned char> v = ArrayToVector(OUTPUT, (unsigned int)PlainText.size());
  delete[] OUTPUT;
  return v;
}
