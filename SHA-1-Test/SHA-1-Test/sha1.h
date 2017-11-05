#pragma once
#include <string>
#include <iostream>

using namespace std;

#define BIT32 0xFFFFFFFF

class SHA1Context
{
public:
	//메세지 다이제스트
	unsigned int digest[5];

	// 비트 단위의 메세지 길이
	unsigned int length_low;
	unsigned int length_high;

	// 512비트 메세지 블록
	unsigned char message_block[64];
	//메세지 블록 배열의 index값을 가리킵니다.
	int          message_block_index;

	// 다이제스트가 계산이 되었는지 확인합니다.
	int          computed;
	
	// 메세지 다이제스트가 엉망이 되었는지 확인합니다.
	int          corrupted;

	SHA1Context() { this->reset(); }
	
	void input(string *message_array);
	void result();
	
protected:
	void reset();
	void process();
	void padding();
};

// word를 bits만큼 좌측 회전 이동합니다.
#define CircularShift(bits, word) \
                ((((word) << (bits)) & BIT32) | \
                ((word) >> (32-(bits))))

inline
static void buffer(
					unsigned temp,
					unsigned &A,
					unsigned &B,
					unsigned &C,
					unsigned &D,
					unsigned &E)
{
	// 법 2^32(32비트) 연산 
	temp &= BIT32;

	E = D;
	D = C;
	C = CircularShift(30, B);
	B = A;
	A = temp;
}