#pragma once

#include "Common.h"

BinaryBuffer Encrypt(const BinaryBuffer& plainText, const EncryptionKey& key);
BinaryBuffer Decrypt(const BinaryBuffer& cipherText, const EncryptionKey& key);

