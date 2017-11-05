#include "sha1.h"
#include <cstdlib>

int main(int argc, char** argv)
{
	SHA1Context *context = new SHA1Context();
	std::string *str = new std::string("12");

	context->input(str);
	context->result();

	cout << "Æò¹® : " << *str << endl;
	cout << "SHA-1: ";
	for (int i = 0; i < 5; i++)
	{
		printf("%x", context->digest[i]);
	}
	cout << endl;
	system("pause");
	return 0;
}