#include "HOTP.h"

/**
* Dynamic Truncation
* truncates string to a string of length 'length' with base 16 (hex)
*/
void HOTP::truncation(unsigned char *& result,char *& str,int length)
{
	char *str_p=str;

	for(int i=0;i<length;++i,str_p+=2)//loop through str. str is a fixed length => increase by 2
	{
		std::string buf(str_p,0,2);
		result[i]=strtol(buf.c_str(),nullptr,16);//copy,pointer to pointer, base
	}
}


int HOTP::computeOffset()
{
	return hmac_result[length-1] & 0xF;
}

int HOTP::computeBinCode(int offset)
{
	return	(hmac_result[offset] & 0x7f) << 24 |
			(hmac_result[offset+1] & 0x7f) << 16 |
			(hmac_result[offset+2] & 0x7f) << 8 |
			(hmac_result[offset+3] & 0x7f);
}



void HOTP::setLength(int l)
{
	length=l;
}

HOTP::HOTP(char *shastr,int length,int trunc)
{
	this->shastr=shastr;
	
	setLength(length);
	resultLength=trunc;

	hmac_result=new unsigned char[resultLength];
}


int HOTP::getLength()
{
	return length;
}

/**
* Computes the HOTP code 
*/
int HOTP::getCode()
{
	truncation(hmac_result,shastr,resultLength);
	int binCode=computeBinCode(computeOffset());
	
	return binCode%_Pow_int(10,6);
}