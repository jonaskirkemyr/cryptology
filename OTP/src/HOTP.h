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
// HOTP.H
// HOTP implementation according to https://tools.ietf.org/html/rfc4226.
// This class support more hash algorithms than specified in [RFC4226], and doesn't 
// therefore follow the standard implementation, as SHA-1 is only supported in [RFC4226].
// This class requires compiled libraries of openssl [https://www.openssl.org/] to work!
// HOTP inherits OTP and creates a HMAC based on input secret and a counter.
//
// Author: Jonas Kirkemyr <jonas@kirkemyr.no>
// ---------------------------------------------------------------------------

#ifndef HOTP_H
#define HOTP_H

#include "OTP.h" 
#include <openssl\hmac.h>
#include <cstdint>//int64_t

using namespace std;
class HOTP: public OTP
{

	private:
		static const int COUNTER_LENGTH=8;

		int64_t counter;//counter for HOTP (used as key with hmac)
		unsigned char * secret;//secret to use with hmac
		int secretLength;//length of secret

		const EVP_MD *algo;//algorithm to use for hmac
		int algoLength;//output length of algorithm used


		/** FUNCTIONS**/
		void increaseCount();

	protected:
		static const unsigned char* toChar(int64_t);//get byte representation of int
		static int64_t toInt(const char*&);//get int representation of char

		void init(unsigned char*,int,int64_t);//init obj
		unsigned char * generateHmac();//generates a hmac with chosen algorithm

		int getAlgoLength();

		const unsigned char * getSecret() const;
		int getSecretLength();

	
	public:
		HOTP(unsigned char*,int,int64_t=0);//set counter
		HOTP(unsigned char*,int,int64_t,int,const EVP_MD*algo=EVP_sha1());
		HOTP();//used by TOTP
		virtual ~HOTP();
		
		int64_t getCounter();
		void setCounter(int64_t);

		void setAlgorithm(const EVP_MD*);//set algorithm

		virtual int getCode();

		void setSecret(unsigned char*,int);
};

#endif