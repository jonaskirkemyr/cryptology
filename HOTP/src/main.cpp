#include "HOTP.h"
#include <iostream>

using namespace std;

int main()
{
	char shastr[]="2923BE84E16CD6AE529049F1F1BBE9EBB3A6DB3C";
	HOTP hotp(shastr);

	cout<<hotp.getCode()<<endl;

	cin.get();
	return 0;
}