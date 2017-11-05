
#include "sha1.h"

void SHA1Context::reset()
{
	this->length_low = 0;
	this->length_high = 0;
	this->message_block_index = 0;

	this->computed = 0;
	this->corrupted = 0;

	this->digest[0] = 0x67452301;
	this->digest[1] = 0xEFCDAB89;
	this->digest[2] = 0x98BADCFE;
	this->digest[3] = 0x10325476;
	this->digest[4] = 0xC3D2E1F0;
}

void SHA1Context::input(string *message_array)
{
	unsigned length = message_array->length();
	const unsigned char *byte_array = (const unsigned char*)message_array->c_str();

	if (!length) return;

	if (this->computed || this->corrupted)
	{
		this->corrupted = 1;
		return;
	}

	while (!(this->corrupted) && length--)
	{
		this->message_block[this->message_block_index++] = (*byte_array & 0xff);
		// 8비트 처리 후 길이값을 8 증가시킵니다.
		this->length_low += 8;

		// 32비트로 강제 변환합니다.
		// C 표준에 의해 32비트가 되는 것이 100% 보장 될수 없습니다. 
		// 이것은 32비트 값만을 보유 할 수 있음을 의미합니다.
		this->length_low &= BIT32;
		if (this->length_low == 0)
		{
			this->length_high++;

			// 강제로 32비트에 만들어줍니다.
			this->length_high &= BIT32;

			// 메세지가 너무 길거나 예외 발생시 다이제스트의 값이 비정상적인 값이 나오므로 오류가 발생합니다.
			if (this->length_high == 0) this->corrupted = 1;
		}

		if (this->message_block_index == 64) this->process();

		byte_array++;
	}
}

void SHA1Context::process()
{
	// SHA-1에서 사용하는 K 상수입니다.
	const unsigned int K[] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	// 임시로 워드를 담습니다.
	unsigned int temp;

	// 워드 시퀸스
	unsigned int W[80];

	// 워드 버퍼
	unsigned int A, B, C, D, E;
	
	// 배열 W의 초기 16개의 단어를 초기화합니다.
	for (int i = 0; i < 16; i++)
	{
		/* String 버퍼를 UINT32_t 배열(MSB)로 변환 */
		W[i]  = ((unsigned)this->message_block[i * 4]    ) << 24;
		W[i] |= ((unsigned)this->message_block[i * 4 + 1]) << 16;
		W[i] |= ((unsigned)this->message_block[i * 4 + 2]) << 8;
		W[i] |= ((unsigned)this->message_block[i * 4 + 3]);
	}

	// 좌측 시프트 1번씩 실행시킵니다.
	for (int i = 16; i < 80; i++)
	{
		W[i] = CircularShift(1, W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]);
	}

	// 초기 워드 버퍼를 지정합니다.
	A = this->digest[0];
	B = this->digest[1];
	C = this->digest[2];
	D = this->digest[3];
	E = this->digest[4];

	//  F(x, y, z)=(x ∧ y) ⊕ (¬ x ∧ z)             (0 ≤ t ≤ 19)
	//  F(x, y, z) = x ⊕ y ⊕ z                 (20 ≤ t ≤ 39)
	//	F(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) (40 ≤ t ≤ 59)
	//	F(x, y, z) = x ⊕ y ⊕ z                 (60 ≤ t ≤ 79)
	for (int i = 0; i < 20; i++)
	{
		temp = CircularShift(5, A) + ((B & C) | (~B & D)) + E + W[i] + K[0];
		buffer(temp, A, B, C, D, E);
	}

	for (int i = 20; i < 40; i++)
	{
		temp = CircularShift(5, A) + (B ^ C ^ D) + E + W[i] + K[1];
		buffer(temp, A, B, C, D, E);

	}

	for (int i = 40; i < 60; i++)
	{
		temp = CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K[2];
		buffer(temp, A, B, C, D, E);
	}

	for (int i = 60; i < 80; i++)
	{
		temp = CircularShift(5, A) + (B ^ C ^ D) + E + W[i] + K[3];
		buffer(temp, A, B, C, D, E);
	}

	this->digest[0] = (this->digest[0] + A) & BIT32;
	this->digest[1] = (this->digest[1] + B) & BIT32;
	this->digest[2] = (this->digest[2] + C) & BIT32;
	this->digest[3] = (this->digest[3] + D) & BIT32;
	this->digest[4] = (this->digest[4] + E) & BIT32;

	this->message_block_index = 0;
}

void SHA1Context::result()
{
	if (this->corrupted) return;
	if (!this->computed)
	{
		this->padding();
		this->computed = 1;
	}
}

/*
표준에 따르면, 메시지는 짝수 512 비트로 채워 져야합니다. 첫 번째 패딩 비트는 1이어야합니다. 
마지막 64비트 자리는 원본 메시지의 길이를 나타냅니다. 그 사이의 모든 비트는 0이어야합니다.
이 함수는 message_block 배열을 채워서 표준 규칙에 따라 메시지를 채웁니다. 또한 process()을 알맞게 호출합니다.
이후, 반환을 할 때 메시지 다이제스트가 계산 된 것으로 간주할 수 있습니다.
*/
void SHA1Context::padding()
{
	if (this->message_block_index > 55)
	{
		this->message_block[this->message_block_index++] = 0x80; /* bit = 10000000 */
		while (this->message_block_index < 64)
			this->message_block[this->message_block_index++] = 0;

		this->process();

		while (this->message_block_index < 56)
			this->message_block[this->message_block_index++] = 0;
	}
	else
	{
		this->message_block[this->message_block_index++] = 0x80;
		while (this->message_block_index < 56)
		{
			this->message_block[this->message_block_index++] = 0;
		}
	}
	this->message_block[56] = (this->length_high >> 24) & 0xFF;
	this->message_block[57] = (this->length_high >> 16) & 0xFF;
	this->message_block[58] = (this->length_high >> 8) & 0xFF;
	this->message_block[59] = (this->length_high) & 0xFF;
	this->message_block[60] = (this->length_low >> 24) & 0xFF;
	this->message_block[61] = (this->length_low >> 16) & 0xFF;
	this->message_block[62] = (this->length_low >> 8) & 0xFF;

	/* 마지막 8비트에 메시지의 길이를 저장합니다. */
	this->message_block[63] = (this->length_low) & 0xFF;

	this->process();
}