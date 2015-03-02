/*
 * MillerRabin.cpp
 *
 *  Created on: 5. feb. 2015
 *      Author: jonastn
 */

#include "../headers/MillerRabin.h"

//private
void MillerRabin::initUV()
{
	if(u > 0 || v>0)
		throw std::exception();
	int n_1=n-1;

	while(n_1%2==0)
	{
		n_1/=2;
		++v;
	}
	u=n_1;
}


//public


/**
 * Init all variables.
 */
MillerRabin::MillerRabin(signed int n):range(2,n-2)//init range
{
	this->n=n;
	this->u=0;
	this->v=0;

	generator=std::default_random_engine();
	std::random_device device;
	generator.seed(device());


}

/**
 * checks if a number is indeed a prime.
 * If COMPOSITE is returned, n is indeed a composite.
 * If PROBABLE_PRIME is returned however, n MAY be composite (prob 1/4)
 *
 * @return States	Whether or not n is prime
 */
States MillerRabin::isPrime()
{
	try
	{
		initUV();//try initializing U&V
	}
	catch(const std::exception& e){}

	const signed long int a=range(generator);
	int b=0;
	(b=((pow(a,this->u))))%=n;


	for(int i=0;i<=this->v;++i)
	{
		if(b==1)
			return PROBABLE_PRIME;
		else
			(b=pow(b,2))%=n;
	
		
	}

	return COMPOSITE;
}

/**
 * Runs the isPrime check k times given by input.
 * This to get a higher probability for n to be indeed a prime
 *
 *@input int	k	#runs
 *@return States	state of number
 */
States MillerRabin::runKtimes(int k)
{
	States state=PROBABLE_PRIME;//assume probable prime
	while(state==PROBABLE_PRIME && k>0)
	{
		state=isPrime();
		--k;
	}

	return state;
}

long int MillerRabin::getV()
{
	return v;
}

long int MillerRabin::getU()
{
	return u;
}
