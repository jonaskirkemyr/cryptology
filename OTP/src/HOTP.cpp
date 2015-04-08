#include "HOTP.h"

/**
* Converts a 64bit int to char
*/
const unsigned char * HOTP::toChar(int64_t number) const
{
	unsigned char *temp=new unsigned char[8];//8bytes (64bit)

	for(int i=8-1;i>=0;--i)//loop through number and copy to char
	{
		temp[i]=(number&0xff);
		number>>=8;
	}
	return temp;
}


/**
* convert a 8byte char to int
*/
int64_t HOTP::toInt(const char*& number)
{
	return
		(((int64_t)number[0]<<56) & 0xff00000000000000U) |
		(((int64_t)number[1]<<48) & 0x00ff000000000000U) |
		(((int64_t)number[2]<<40) & 0x0000ff0000000000U) |
		(((int64_t)number[3]<<32) & 0x000000ff00000000U) |
		(((int64_t)number[4]<<24) & 0x00000000ff000000U) |
		(((int64_t)number[5]<<16) & 0x0000000000ff0000U) |
		(((int64_t)number[6]<<8)  & 0x000000000000ff00U) |
		(((int64_t)number[7])	  & 0x00000000000000ffU);
}


unsigned char * HOTP::generateHmac()
{
	return HMAC(this->algo,
				this->secret,//shared secret
				this->secretLength,//length of secret
				this->toChar(this->counter),//counter to char
				8,//length of counter (8bytes)
				0,0);//don't copy to any vars
}

/**
* Set length of one time password, and generates a HMAC-SHA-1 
* from input secret and counter
*/
void HOTP::initOTP(int codeLength)
{
	this->setLength(codeLength);
	this->setHmac(this->generateHmac(),this->algoLength);
}

void HOTP::setSecretAndCount(unsigned char * secret,int secretLength,int64_t c)
{
	this->counter=c;
	this->secretLength=secretLength;
	
	this->secret=new unsigned char[this->secretLength];

	for(int i=0;i<this->secretLength;++i)
		this->secret[i]=secret[i];
	this->secret[this->secretLength]='\0';
}


HOTP::HOTP(unsigned char * secret,int secretLength,int64_t c) : OTP()
{
	this->setSecretAndCount(secret,secretLength,c);
}

HOTP::HOTP(unsigned char * secret, int secretLength,int64_t c,int codeLength,const EVP_MD*algo) : OTP()
{
	this->setSecretAndCount(secret,secretLength,c);
	this->initHOTP(codeLength,algo);
}


void HOTP::initHOTP(int codeLength,const EVP_MD *algo)
{
	this->setAlgorithm(algo);
	this->initOTP(codeLength);
}


int64_t HOTP::getCounter()
{
	return this->counter;
}

void HOTP::setCounter(int64_t c)
{
	this->counter=c;
}

/**
* Sets the algorithm to use for HMAC.
* The length of returned hmac is stored 
* with each algorithm.
* default is set as sha1. 
* @param const EVP_MD*	algo	algorithm to use
*/
void HOTP::setAlgorithm(const EVP_MD* algo)
{
	switch(EVP_MD_type(algo))
	{
		case NID_sha224://224bits=28bytes
			this->algoLength=28;
			this->algo=EVP_sha224();
		break;

		case NID_sha256://256bits=32bytes
			this->algoLength=32;
			this->algo=EVP_sha256();
		break;

		case NID_sha384://384bits=48bytes
			this->algoLength=48;
			this->algo=EVP_sha384();
		break;

		case NID_sha512://512bits=64bytes
			this->algoLength=64;
			this->algo=EVP_sha512();
		break;

		case NID_sha1://160bits=20bytes
		default:
			this->algoLength=20;
			this->algo=EVP_sha1();
		break;
	}
}