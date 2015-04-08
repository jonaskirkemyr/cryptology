#include "OTP.h"

/**
* Dynamic Truncation
* truncates string to a string of length 'length' with base 16 (hex)
*/
void OTP::truncation(unsigned char *& result, char *& str,int length)
{
	char *str_p=str;

	for(int i=0;i<length;++i,str_p+=2)//loop through str. str is a fixed length => increase by 2
	{
		std::string buf(str_p,0,2);
		result[i]=strtol(buf.c_str(),nullptr,16);//copy,pointer to pointer, base
	}
}


int OTP::computeOffset()
{
	return hmac_result[resultLength-1] & 0xF;
}

int OTP::computeBinCode(int offset)
{
	return	(hmac_result[offset] & 0x7f) << 24 |
			(hmac_result[offset+1] & 0xff) << 16 |
			(hmac_result[offset+2] & 0xff) << 8 |
			(hmac_result[offset+3] & 0xff);
}


void OTP::freeHmac()
{
	delete [] this->hmac_result;
	this->hmac_result=nullptr;
}




void OTP::setLength(int l)
{
	length=l;
}

/**
* set a shastr, which need to be trunctated to a <length>byte string
* @param char *		shastr		shastr to trunctate
* @param int		length		length of one-time-password
* @param int		trunc		bytes to trunctate shastr to
*/
OTP::OTP(char *shastr,int length,int trunc)
{	
	setLength(length);
	resultLength=trunc;

	hmac_result=new unsigned char[resultLength];

	truncation(hmac_result,shastr,resultLength);
}

/**
* Copy a hmac-shax to obj
* @param unsigned char*			hmac		hmac-shax computed string
* @param int					length		length of one-time-password
* @param int					trunc		length of hmac-shax string
*/
OTP::OTP(unsigned char* hmac,int length,int trunc)
{
	setLength(length);
	resultLength=trunc;

	hmac_result=new unsigned char[resultLength];
	for(int i=0;i<this->resultLength;++i)
		this->hmac_result[i]=hmac[i];
	this->hmac_result[this->resultLength]='\0';
}

OTP::OTP()
{
	//init variables
	setLength(0);

	resultLength=0;
	hmac_result=nullptr;
}

OTP::~OTP()
{
	freeHmac();
}


int OTP::getLength()
{
	return length;
}

/**
* Computes the HOTP code 
*
* If a shastr is added, truncation is needed to be called
* before getting code!
*/
int OTP::getCode()
{
	int binCode=computeBinCode(computeOffset());
	
	return binCode%_Pow_int(10,6);
}

void OTP::setHmac(unsigned char *hmac)
{
	if(this->hmac_result!=nullptr)//check if data is added to hmac before adding new data
		freeHmac();

	resultLength=strlen((char*)hmac);
	//resultLength=sizeof(hmac);
	hmac_result=new unsigned char[resultLength];

	for(int i=0;i<resultLength;++i)//copy hmac->hmac_result
		hmac_result[i]=hmac[i];
}

void OTP::setShaStr(char * shastr,int length)
{
	if(this->hmac_result!=nullptr)//check if data is added to hmac before adding new data
		freeHmac();

	this->resultLength=length;
	truncation(hmac_result,shastr,this->resultLength);
}