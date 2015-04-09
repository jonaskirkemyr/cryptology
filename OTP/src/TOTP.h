#ifndef TOTP_H
#define TOTP_H

#include "HOTP.h"
#include <ctime>//time()


class TOTP : public HOTP
{
	private:
		static const int T0=0;//start count (unix epoch)

		int timestep;

		int computeCounter();


	public:
		TOTP(int=30);//timestep
		TOTP(unsigned char*,int,int=30);
		TOTP(unsigned char*,int,int,int,const EVP_MD*algo=EVP_sha1());//secret,secretLength,codeLength,timestep,algo

		virtual int getCode();

};

#endif