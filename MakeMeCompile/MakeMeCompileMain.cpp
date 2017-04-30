#include "TopSecretLib.h"
#include "Encryption.h"
#include <iostream>
#include <string>
#include <map>

BinaryBuffer GetEncryptedBuffer()
{
	std::string str = "Password";
	for (size_t i = 0; i < str.length(); i++)
	{
		str[i] += 1;
	}
	
	if (str[4] != 120)
	{
		return SomeFunction9936();
	}
	else
	{
		return SomeFunction145();
	}
}

BinaryBuffer GetEncryptionKey()
{
	short i = 15;
	short c = i % 6;
	if (c > 6)
	{
		return SomeFunction1839();
	}
	std::vector<char> v;
	for (; i < 100; ++i)
	{
		v.emplace_back(i);
	}

	return (v.size() > 80) ? SomeFunction1362() : SomeFunction4932();
}

void main()
{
	const BinaryBuffer encryptedBuffer = GetEncryptedBuffer();
	const BinaryBuffer encryptionKey = GetEncryptionKey();
	const BinaryBuffer passwordBinary = Decrypt(encryptedBuffer, encryptionKey);
	const std::string password(passwordBinary.cbegin(), passwordBinary.cend());
			
	std::cout << password << std::endl;
	system("pause");
}