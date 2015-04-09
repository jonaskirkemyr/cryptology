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
// OTP.H
// Generalization of OTP. The purpose of this class is to compute a One-Time-Password
// given a shastring, or byte array created by a HMAC function (openssl)[https://www.openssl.org/].
// This class can be used by any HMAC function, openssl is just an example!
// The OTP length can be set, and will return #digits specified 
//
// Author: Jonas Kirkemyr <jonas@kirkemyr.no>
// ---------------------------------------------------------------------------

#ifndef OTP_H
#define OTP_H

#include <string>
#include <cmath>

class OTP
{
	private:
		int length;//length of one-time password
	
		unsigned char *hmac_result;//hmac generated
		int resultLength;//length of hmac


		/** FUNCTIONS**/
		static void truncation(unsigned char *&, char *&,int=20);//truncated string, string to truncate, size of truncated string
		
		int computeOffset();//compute offset of hmac
		int computeBinCode(int);//offset

		virtual void freeHmac();//delete hmac_result

	protected:
		void setHmac(unsigned char *,int);//hmac
		void setShaStr(char*,int=20);//shastring, sha length

	public:
		OTP(char *,int=6,int=20);//shastr, length of truncate
		OTP(unsigned char*,int=6,int=20);//hmac_sha1,length of code, length of hmac
		OTP();
		virtual ~OTP();

		void setLength(int);//set length of OTP
		int getLength();//get length of OTP

		virtual int getCode();//generate and return OTP

};



#endif