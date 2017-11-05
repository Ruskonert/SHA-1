#pragma once
#include <string>
#include <iostream>

using namespace std;

#define BIT32 0xFFFFFFFF

class SHA1Context
{
public:
	//�޼��� ��������Ʈ
	unsigned int digest[5];

	// ��Ʈ ������ �޼��� ����
	unsigned int length_low;
	unsigned int length_high;

	// 512��Ʈ �޼��� ���
	unsigned char message_block[64];
	//�޼��� ��� �迭�� index���� ����ŵ�ϴ�.
	int          message_block_index;

	// ��������Ʈ�� ����� �Ǿ����� Ȯ���մϴ�.
	int          computed;
	
	// �޼��� ��������Ʈ�� ������ �Ǿ����� Ȯ���մϴ�.
	int          corrupted;

	SHA1Context() { this->reset(); }
	
	void input(string *message_array);
	void result();
	
protected:
	void reset();
	void process();
	void padding();
};

// word�� bits��ŭ ���� ȸ�� �̵��մϴ�.
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
	// �� 2^32(32��Ʈ) ���� 
	temp &= BIT32;

	E = D;
	D = C;
	C = CircularShift(30, B);
	B = A;
	A = temp;
}