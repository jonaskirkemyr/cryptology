/*
 * MillerRabin.h
 *
 *  Created on: 5. feb. 2015
 *      Author: jonastn
 *
 *  MillerRabin checks if a given number is prime
 */

#ifndef MILLERRABIN_H
#define MILLERRABIN_H

#include <random>
#include <exception>
#include <cmath>

enum States
{
	PROBABLE_PRIME=0,
	COMPOSITE

};


class MillerRabin
{
	private:
		int u;
		int v;
		signed int n;//number to check

		std::default_random_engine generator;
		std::uniform_int_distribution<signed int> range;

		void initUV();//computes uv

	public:
		MillerRabin(signed int);//n
		

		States isPrime();
		States runKtimes(int);//k

		long int getU();
		long int getV();



};



#endif /* MILLERRABIN_H_ */
