#ifndef HOTP_H
#define HOTP_H

#include "OTP.h" 
#include <openssl\hmac.h>
#include <cstdint>//int64_t

using namespace std;
class HOTP: public OTP
{

	private:
		int64_t counter;
		unsigned char * secret;
		int secretLength;


		const unsigned char* toChar(int64_t) const;
		int64_t toInt(const char*&);

		unsigned char * generateHmac(const EVP_MD*algo=EVP_sha1());
		void initOTP(int=6);

	public:
		HOTP(unsigned char*,int,int=6,int64_t=0);//set counter

		int64_t getCounter();
		void setCounter(int64_t);


};

#endif