#ifndef OTP_H
#define OTP_H

#include <string>
#include <cmath>

class OTP
{
	private:
		static void truncation(unsigned char *&, char *&,int=20);//truncated string, string to truncate, size of truncated string
		
		int computeOffset();
		int computeBinCode(int);//offset

		int length;//length of one-time password
	
		unsigned char *hmac_result;
		int resultLength;

		void freeHmac();//delete hmac_result

	protected:
		void setHmac(unsigned char *);//hmac
		void setShaStr(char*,int=20);//shastring, sha length

	public:
		OTP(char *,int=6,int=20);//shastr, length of truncate
		OTP(unsigned char*,int=6,int=20);//hmac_sha1,length of code, length of hmac
		OTP();
		virtual ~OTP();

		void setLength(int);
		int getLength();

		int getCode();

};



#endif