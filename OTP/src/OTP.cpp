#include "OTP.h"

//  .#####...#####...######..##..##...####...######..######.
//  .##..##..##..##....##....##..##..##..##....##....##.....
//  .#####...#####.....##....##..##..######....##....####...
//  .##......##..##....##.....####...##..##....##....##.....
//  .##......##..##..######....##....##..##....##....######.
//  ........................................................

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

/**
* Computes offset of hmac_result.
* get the last byte from string
*/
int OTP::computeOffset()
{
	return hmac_result[resultLength-1] & 0xF;
}

/** 
* Extract dynamic bin code.
* TODO: Support more algorithms than sha1!
* @param int	offset	last byte in hmac from computeOffset()
*/
int OTP::computeBinCode(int offset)
{
	return	(hmac_result[offset] & 0x7f) << 24 |
			(hmac_result[offset+1] & 0xff) << 16 |
			(hmac_result[offset+2] & 0xff) << 8 |
			(hmac_result[offset+3] & 0xff);
}

/**
* Free memory of variables dynamic allocated
*/
void OTP::freeHmac()
{
	delete [] this->hmac_result;
	this->hmac_result=nullptr;
}





//  .#####...#####....####...######..######...####...######..######..#####..
//  .##..##..##..##..##..##....##....##......##..##....##....##......##..##.
//  .#####...#####...##..##....##....####....##........##....####....##..##.
//  .##......##..##..##..##....##....##......##..##....##....##......##..##.
//  .##......##..##...####.....##....######...####.....##....######..#####..
//  ........................................................................

/**
* set already created HMAC to hmac_result
* and its length. If a HMAC is already set,
* the hmac is deleted before assigning new data.
* @param unsigned char*		hmac	hmac generated
* @param int				length	length of hmac
*/
void OTP::setHmac(unsigned char *hmac,int length)
{
	if(this->hmac_result!=nullptr)//check if data is added to hmac before adding new data
		freeHmac();//free hmac if already set

	resultLength=length;

	hmac_result=new unsigned char[resultLength];

	for(int i=0;i<resultLength;++i)//copy hmac->hmac_result
		hmac_result[i]=hmac[i];
}

/**
* Set a SHAstr to hmac_result. The SHAstr is truncated
* to fit hmac_result (20bytes). 
* If a HMAC is already sey, the HMAC is deleted before
* assigning new data
* @param char*	shastr	shastr to copy and truncate to hmac_result
* @param int	length	length of shastr
*/
void OTP::setShaStr(char * shastr,int length)
{
	if(this->hmac_result!=nullptr)//check if data is added to hmac before adding new data
		freeHmac();//free hmac if already set

	this->resultLength=length;
	truncation(hmac_result,shastr,this->resultLength);//truncate and copy value to hmac_result
}




//  .#####...##..##..#####...##......######...####..
//  .##..##..##..##..##..##..##........##....##..##.
//  .#####...##..##..#####...##........##....##.....
//  .##......##..##..##..##..##........##....##..##.
//  .##.......####...#####...######..######...####..
//  ................................................


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
* Copy a hmac-sha<x> to obj
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


/**
* Set length of OTP.
* @param int	l	length of OTP to set
*/
void OTP::setLength(int l)
{
	length=l;
}

/**
* get length of OTP 
* @return int length of OTP
*/
int OTP::getLength()
{
	return length;
}

/**
* Computes the OTP code 
*
* If a shastr is added, truncation is needed to be called
* before getting code!
* @return int OTP 
*/
int OTP::getCode()
{
	int binCode=computeBinCode(computeOffset());
	
	return binCode%_Pow_int(10,6);
}

