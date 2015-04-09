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

#include "TOTP.h"

/**
* Computes current counter from timestamp
* Supported year: 2038 => 32 bit int
*/
int TOTP::computeCounter()
{
	return (std::time(nullptr)-T0)/timestep;
}


/**
* Set timestep for TOTP. 
* @param int	timestep	interval for counter since epoch time
*/
TOTP::TOTP(int timestep) : HOTP()
{
	this->timestep=timestep;
}

/**
* Set secret with a timestep
* @param unsigned char *	secret			secret to base HMAC on
* @param int				secretLength	length of secret
* @param int				timestep		timestep for timestamp
*/
TOTP::TOTP(unsigned char* secret, int secretLength, int timestep) : HOTP()
{
	this->timestep=timestep;
	this->init(secret,secretLength,0);//counter don't need to be set before retriaval of OTP
}


/**
* Set secret, codelength, timestep and alogrithm to use with TOTP
* @param unsigned char *	secret			secret to base HMAC on
* @param int				secretLength	length of secret
* @param int				codeLength		length of OTP
* @param int				timestep		timestep for timestamp
* @param const EVP_MD*		algo			algorithm to use for HMAC
*/
TOTP::TOTP(unsigned char* secret,int secretLength,int codeLength,int timestep,const EVP_MD*algo) : HOTP()
{
	this->timestep=timestep;

	this->init(secret,secretLength,0);//counter don't need to be set before retriaval of OTP
	this->setAlgorithm(algo);
	this->setLength(codeLength);
}


TOTP::~TOTP()
{

}


/**
* Generates a HMAC-SHA-1 
* from input secret and computed 
* counter from timestamp
*/
int TOTP::getCode()
{
	if(this->getAlgoLength()==0)
		throw "Algorithm need to be set";
	if(this->getLength()==0)
		throw "Length of one-time password not set";
	if(this->getSecret()==nullptr)
		throw "Secret not set";
	if(this->getLength()==0)
		throw "OTP length not set";

	this->setCounter(this->computeCounter());
	this->setHmac(this->generateHmac(),this->getAlgoLength());
	return OTP::getCode();
}