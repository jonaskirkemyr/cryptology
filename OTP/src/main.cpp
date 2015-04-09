#include "HOTP.h"
#include "OTP.h"
#include "TOTP.h"
#include <iostream>
#include <iomanip>

#include <openssl/hmac.h>

using namespace std;

int main()
{
	cout<<setfill('0');//add 0 in front of numbers

	unsigned char* digest;
	unsigned char test[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char data[]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30};
  

	//TEST HEXADECIMAL OUTPUT
	/** should output:
		cc93cf18508d94934c64b65d8ba7667fb7cde4b0
	**/
	cout<<"TEST HEXADECIMAL:"<<endl;
	digest = HMAC(EVP_sha1(), data,sizeof(data),test,sizeof(test), NULL, NULL);    

	cout<<"hmac-sha-1:\n";
	for(int i=0;i<20;i++)
    std::cout << setfill('0') << setw(2) << hex << (int)digest[i];
	cout<<"\nend\n";

	OTP otp1(digest);
	cout<<setw(6);
	cout<<dec<<otp1.getCode()<<endl;
	cout<<"END TEST HEXADECIMAL:"<<endl<<endl;

	

	//TEST CONSTRUCTOR - NEED TO SPECIFY ALGO AND OTP LENGTH
	cout<<"TEST SPECIFIED ALGO AND LENGTH:"<<endl;
	HOTP hotp(data,sizeof(data),0);
	hotp.setLength(8);
	hotp.setAlgorithm(EVP_sha1());

	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<hotp.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}
	cout<<"END TEST SPECIFIED ALGO AND LENGTH:"<<endl<<endl;


	//TEST EXCEPTION
	cout<<"TEST EXCEPTION:"<<endl;
	HOTP hotp1(data,sizeof(data),0);
	try{
		cout<<setw(6);//specify expected length of output
		cout<<dec<<hotp1.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}
	cout<<"END TEST EXCEPTION:"<<endl<<endl;

	//TEST CONSTRUCTOR ALL INPUT
	cout<<"TEST ALL INPUT:"<<endl;
	HOTP hotp2(data,sizeof(data),0,6,EVP_sha1());

	try{
		cout<<setw(6);//specify expected length of output
		cout<<dec<<hotp2.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}
	cout<<"END TEST ALL INPUT:"<<endl<<endl;
	

	
	//TEST RFC4226 DATA (Appendix D [http://www.ietf.org/rfc/rfc4226.txt])
	/** should output:
			0	-	755224
			1	-	287082
			2	-	359152
			3	-	969429
			4	-	338314
			5	-	254676
			6	-	287922
			7	-	162583
			8	-	399871
			9	-	520489
	**/
	cout<<"TEST RFC4226:"<<endl;
	HOTP hotp3(data,sizeof(data),0,6,EVP_sha1());

	for(int i=0;i<10;++i)
	{
		try{
			cout<<setw(6);//specify expected length of output
			cout<<dec<<hotp3.getCode()<<endl;
		}catch(const char* e){
			cout<<e<<endl;
		}
	}

	cout<<"END TEST RFC4226"<<endl<<endl;


	//TEST TOTP TIMESTEP CONSTRUCTOR
	cout<<"TEST TOTP TIMESTEP CONSTRUCTOR:"<<endl;
	TOTP totp(30);
	totp.setSecret(data,sizeof(data));
	totp.setAlgorithm(EVP_sha1());
	totp.setLength(8);
	
	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<totp.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}

	cout<<"END TEST TOTP:"<<endl<<endl;



	//TEST TOTP SECRET, TIMESTAMP CONTRUCTOR
	cout<<"TEST TOTP SECRET-TIMESTEP CONSTRUCTOR:"<<endl;
	TOTP totp1(data,sizeof(data),30);
	totp1.setAlgorithm(EVP_sha1());
	totp1.setLength(8);
	
	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<totp1.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}

	cout<<"END TEST TOTP SECRET-TIMESTEP CONSTRUCTOR:"<<endl<<endl;

	//TEST FULL CONSTRUCTOR
	cout<<"TEST TOTP FULL CONSTRUCTOR:"<<endl;
	TOTP totp2(data,sizeof(data),8,30);	
	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<totp2.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}

	cout<<"END TEST TOTP FULL CONSTRUCTOR:"<<endl<<endl;



	//TEST SHA256 TOTP
	unsigned char data256[]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,
							0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32
							};

	cout<<"TEST TOTP SHA256:"<<endl;
	TOTP totp3(data256,sizeof(data256),8,30,EVP_sha256());	
	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<totp3.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}
	cout<<"END TEST TOTP SHA256:"<<endl<<endl;


	//TEST SHA512 TOTP
	unsigned char data512[]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,
							 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,
							 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,
							 0x31,0x32,0x33,0x34
							};

	cout<<"TEST TOTP SHA512:"<<endl;
	TOTP totp4(data512,sizeof(data512),8,30,EVP_sha512());	
	try{
		cout<<setw(8);//specify expected length of output
		cout<<dec<<totp4.getCode()<<endl;
	}catch(const char* e){
		cout<<e<<endl;
	}
	cout<<"END TEST TOTP SHA512:"<<endl<<endl;


	return 0;
}

