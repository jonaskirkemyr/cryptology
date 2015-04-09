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