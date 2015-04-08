#include "HOTP.h"
#include "OTP.h"
#include <iostream>
#include <iomanip>

#include <openssl/hmac.h>

using namespace std;

int main()
{
	char shastr[]="cc93cf18508d94934c64b65d8ba7667fb7cde4b0";
	OTP otp(shastr);

	cout<<otp.getCode()<<endl;

	unsigned char* digest;
    char key[] = "0";

	unsigned char test[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};

	unsigned char data[]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30};
	
  
	digest = HMAC(EVP_sha1(), data,sizeof(data),test,sizeof(test), NULL, NULL);    

	cout<<"hmac-sha-1:\n";
	for(int i=0;i<20;i++)
    std::cout << setfill('0') << setw(2) << hex << (int)digest[i];
	cout<<"\nend\n";

	OTP otp1(digest);

	cout<<dec<<otp1.getCode()<<endl;

	HOTP hotp(data,sizeof(data),6,1);
	cout<<dec<<hotp.getCode()<<endl;

	cin.get();
	return 0;
}

