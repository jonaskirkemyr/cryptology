// ---------------------------------------------------------------------------
// The MIT License (MIT)
//
//Copyright (c) 2015 Jonas Kirkemyr 
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author: Jonas Kirkemyr <jonas@kirkemyr.no>
// ---------------------------------------------------------------------------

#include "HOTP.h"

/**
* Increases the counter after use
*/
void HOTP::increaseCount()
{
	this->counter++;
}

//  .#####...#####....####...######..######...####...######..######..#####..
//  .##..##..##..##..##..##....##....##......##..##....##....##......##..##.
//  .#####...#####...##..##....##....####....##........##....####....##..##.
//  .##......##..##..##..##....##....##......##..##....##....##......##..##.
//  .##......##..##...####.....##....######...####.....##....######..#####..
//  ........................................................................

/**
* Converts a 64bit int to char
*/
const unsigned char * HOTP::toChar(int64_t number)
{
	unsigned char *temp=new unsigned char[COUNTER_LENGTH];//8bytes (64bit)

	for(int i=COUNTER_LENGTH-1;i>=0;--i)//loop through number and copy to char
	{
		temp[i]=(number&0xff);
		number>>=COUNTER_LENGTH;
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

/**
* init HOTP vars and copy set vars to local variables
*/
void HOTP::init(unsigned char * secret,int secretLength,int64_t c)
{
	this->algoLength=0;

	this->counter=c;
	this->secretLength=secretLength;
	
	this->secret=new unsigned char[this->secretLength];

	for(int i=0;i<this->secretLength;++i)//copy secret to local var
		this->secret[i]=secret[i];
}

/**
* Generates a HMAC-ALGORITHM by set secret
* and counter
* @TODO FREE toChar!
*/
unsigned char * HOTP::generateHmac()
{
	return HMAC(this->algo,
				this->secret,//shared secret
				this->secretLength,//length of secret
				this->toChar(this->counter),//counter to char
				COUNTER_LENGTH,//length of counter (8bytes)
				0,0);//don't copy to any vars
}


/**
* get length of algorithm output
*/
int HOTP::getAlgoLength()
{
	return this->algoLength;
}

/**
* returns the secret as const pointer
*/
const unsigned char * HOTP::getSecret() const
{
	return this->secret;
}

/**
* Returns length of secret
*/
int HOTP::getSecretLength()
{
	return this->secretLength;
}


//  .#####...##..##..#####...##......######...####..
//  .##..##..##..##..##..##..##........##....##..##.
//  .#####...##..##..#####...##........##....##.....
//  .##......##..##..##..##..##........##....##..##.
//  .##.......####...#####...######..######...####..
//  ................................................


/**
* set secret and counter for HOTP. 
* Algorithm and OTP length needs to be set
* before OTP code can be retrieved!
*/
HOTP::HOTP(unsigned char * secret,int secretLength,int64_t c) : OTP()
{
	this->init(secret,secretLength,c);
}

/**
* Constructor for all needed input to use HOTP
*/
HOTP::HOTP(unsigned char * secret, int secretLength,int64_t c,int codeLength,const EVP_MD*algo) : OTP()
{
	this->init(secret,secretLength,c);
	this->setAlgorithm(algo);
	this->setLength(codeLength);
}

HOTP::HOTP() : OTP()
{
	secretLength=0;
	secret=nullptr;
	counter=0;
	algoLength=0;
}

HOTP::~HOTP()
{
	delete[] secret;
	secret=nullptr;
}

/**
* returns counter registered for HOTP
*/
int64_t HOTP::getCounter()
{
	return this->counter;
}

/**
* Get current counter for HOTP
*/
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

/**
* Generates a HMAC-SHA-1 
* from input secret and counter
*/
int HOTP::getCode()
{
	if(this->algoLength==0)
		throw "Algorithm need to be set";
	if(this->getLength()==0)
		throw "Length of one-time password not set";
	if(secret==nullptr)
		throw "Secret not set";
	if(this->getLength()==0)
		throw "OTP length not set";

	this->setHmac(this->generateHmac(),this->algoLength);
	increaseCount();//increase counter
	return OTP::getCode();
}

/**
* Sets the secret to base HMAC on
* If secret is already set, exception is thrown
*/
void HOTP::setSecret(unsigned char* secret,int secretLength)
{
	if(this->secret!=nullptr)
		throw "Secret already set";

	this->init(secret,secretLength,counter);
}