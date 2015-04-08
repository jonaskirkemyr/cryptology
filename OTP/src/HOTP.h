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
		const unsigned char* toChar(int64_t) const;//get byte representation of int
		int64_t toInt(const char*&);//get int representation of char

		unsigned char * generateHmac();//generates a hmac with chosen algorithm
		void init(unsigned char*,int,int64_t);//init obj

		void increaseCount();

	public:
		HOTP(unsigned char*,int,int64_t=0);//set counter
		HOTP(unsigned char*,int,int64_t,int,const EVP_MD*algo=EVP_sha1());
		
		int64_t getCounter();
		void setCounter(int64_t);

		void setAlgorithm(const EVP_MD*);//set algorithm

		virtual int getCode();
};

#endif