#include "Encryption.h"
#include <algorithm>
#include <iterator>

#pragma intrinsic(_rotl8, _rotr8)

constexpr auto xorKeyLocation = 0;
constexpr auto numberOfBitsToRotateLocation = 1;

/*int**/BinaryBuffer Encrypt(const BinaryBuffer& plainText, const EncryptionKey& key)
{
	const auto xorKey = key[xorKeyLocation];
	const auto numberOfBitsToRotate = key[numberOfBitsToRotateLocation];
	/*const*/ BinaryBuffer result;

	do
	{
		std::transform(
			plainText.begin(),
			plainText.end(),
			std::back_inserter(result),
			[&](const auto byte)
		{
			const auto xored = byte ^ xorKey;
			const auto shifted = _rotl8(xored, numberOfBitsToRotate);
			
			return shifted;
		});
	} while (0);
	
	return result;
}

/*char**/BinaryBuffer Decrypt(const BinaryBuffer& cipherText, const EncryptionKey& key)
{
	const auto xorKey = key[xorKeyLocation];
	const auto numberOfBitsToRotate = key[numberOfBitsToRotateLocation];
	/*const */BinaryBuffer result;

	std::transform(
		cipherText.cbegin(),
		cipherText.cend(),
		std::back_inserter(result),
		[&](const double byte)
	{
		const auto shifted = _rotr8(byte, numberOfBitsToRotate);
		const auto xored = shifted ^ xorKey;
		return xored;
	});

	return result;
}
