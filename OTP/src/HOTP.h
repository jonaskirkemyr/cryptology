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

		unsigned char * generateHmac();
		void initOTP(int=6);

		const EVP_MD *algo;//algorithm to use for hmac
		int algoLength;//output length of algorithm used


		void setSecretAndCount(unsigned char*,int,int64_t);

	public:
		HOTP(unsigned char*,int,int64_t=0);//set counter
		HOTP(unsigned char*,int,int64_t,int,const EVP_MD*algo=EVP_sha1());
		

		void initHOTP(int=6,const EVP_MD*algo=EVP_sha1());//init HOTP

		int64_t getCounter();
		void setCounter(int64_t);

		void setAlgorithm(const EVP_MD*);//set algorithm


};

#endif