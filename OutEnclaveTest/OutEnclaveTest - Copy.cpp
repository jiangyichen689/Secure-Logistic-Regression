/******************************************************************************
 * CHANGE TO CONSISTENT VARIABLE NAMING STYLE - EITHER ALL CAMEL CASE, OR 
 * underscore_style!!!
 * 
 * Package: SecureLR
 * Authors: J. Hamer, Y. Jiang
 * Filename: OutEnclaveTest.cpp (RENAME ALL FILES)
 *
 * Description: 
 * 
 * 
 * Functions: 
 *
 *
 *****************************************************************************/
#include "SealEnclaveTest_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include "Matrix.h"
#include <vector>
#include <algorithm>
#include <math.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <unordered_map>
#include <ctime>
#include <numeric>
#include "../Seal_OutEnclave/seal.h"
#include "TestData.h"
//#include "ReadData.h"
#include "MakeConfigure.h"

using namespace std;
using namespace seal;

#define ENCLAVE_FILE _T("SealEnclaveTest.signed.dll")
#define MAX_BUF_LEN 600000
#define round(x) (x - floor(x) >= 0.5 ? floor(x) + 1 : floor(x)) 
#define SIGNIFICANT_FIGURES 0
//#define Simplify_NewSigmoid
#define DEBUG
#define SHOWRESULT

//vector<vector<double>> X;
//vector<double> Y;

EncryptionParameters  parms;
sgx_enclave_id_t      eid;
vector<BigPolyArray>  Hash_index;
vector<BigPolyArray>  Hash_result;
BigPolyArray          public_key;
#if defined (DEBUG) || defined(SHOWRESULT)
BigPoly               secret_key;
#endif // DEBUG
#ifdef SHOWRESULT
//vector<int>           idxVector;
vector<vector<int>>   orderOfRandomTraining;
vector<int>           trainV;
vector<int>           testV;
#endif


BigPoly one;
BigPolyArray y_0;
BigPoly plain_3;
vector<vector<BigPolyArray>> noise; // in each vector, first is random num, second is sum


/******************************************************************************
 * struct: Configure
 * 
 * Description: contains the SecureLR parameters
 * HME parameters: 
 *		::p_poly_modulus::
 *		::p_coeff_modulus::
 *		::p_plain_modulus::
 *		::precision::
 *		::encoder_conf::
 *
 * Logistic Regression hyperparameters:
 *		::learning_rate::
 *		::num_epochs::
 * 
 * Sigmoidal approximation:
 *		::Sigmoid_itor::
 *		::Sigmoid_y_initial::
 *****************************************************************************/
static struct Configure
{

	// configure for HME parameters
	string p_poly_modulus;
	int p_coeff_modulus;
	int p_plain_modulus;
	int precision;
	vector<int> encoder_conf;

	// Logistic Regression Parameters -- CHANGE TO CONSISTENT VARIABLE NAMING STYLE
	double learningRate;
	int numEpochs;
	vector<double> maxItor;
	vector<double> psamples;

	// Sigmoid function approximation using an Inverse Square Root function
	// Approximation method: Newton-Raphson iterative method (req. y_initial)
	int Sigmoid_itor;
	double Sigmoid_y_inital;
	
} config;



/******************************************************************************
* Function name: Round() 
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
double Round(double value)
{
	int n = SIGNIFICANT_FIGURES;
	return round(value * pow(10, n)) / pow(10, n);
}



/******************************************************************************
* Function name: Create_Vector_By_Step
* Parameters: 
*
* Description: 
* Return:
******************************************************************************/
void Create_Vector_By_Step(vector<double>& tmpVector, double start, double step, double end)
{
	for (double i = start; i <= end; i += step)
		tmpVector.push_back(i);
}



#if defined (DEBUG) || defined(SHOWRESULT)
/******************************************************************************
* Function name: DecryptForDebug()
* Parameters: input, a BigPolyArray
*
* Description: decrypts ::input:: into a double
* Return: ::input:: as a decrypted double
******************************************************************************/
double DecryptForDebug(BigPolyArray input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, secret_key);
	int ans = encoder.decode_int32(decryptor.decrypt(input));
	return ans;
}




/******************************************************************************
* Function name: EncryptToEncode
* Parameters: value, a BigPolyArray
*
* Description: encodes a BigPolyArray into a BigPoly
* Return: a BigPoly
******************************************************************************/
BigPoly EncryptToEncode(BigPolyArray input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, secret_key);
	BigPoly ans = decryptor.decrypt(input);
	return ans;
}
#endif




/******************************************************************************
* Function name: Encoder()
* Parameters: input, an integer
*
* Description: encodes the ::input:: into an encoded BigPoly
* Return: a BigPoly
******************************************************************************/
BigPoly Encoder(int input)
{
	IntegerEncoder encoder(parms.plain_modulus());

	BigPoly encodeNumber = encoder.encode(input);
	return encodeNumber;
}




/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
BigPolyArray Encryption(int input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);

	BigPolyArray enc=encryptor.encrypt(encoder.encode(input));
	return enc;
}




/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
BigPolyArray DecreaseNoise(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	DecreaseNoise_SGX(eid, buffer, buffer_length,trainingSize,config.Sigmoid_y_inital);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}




/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
BigPolyArray Reline(BigPolyArray input)
{
	parms.decomposition_bit_count() = 10;

	KeyGenerator generator(parms);
	generator.generate();

	generator.generate_evaluation_keys(input.size() - 2);
	EvaluationKeys evaluation_keys = generator.evaluation_keys();
	Evaluator evaluator2(parms, evaluation_keys);
	input = evaluator2.relinearize(input);

	return input;
}




/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
double GetRandom(double min, double max) 
{
	/* Returns a random double between min and max */
	return ((double) rand() * (max - min) / (double) RAND_MAX - min);
}




/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
BigPolyArray HashCiphertext(BigPolyArray input,int index)
{
	Evaluator evaluator(parms);
	BigPolyArray tmp1= evaluator.add(input, evaluator.negate(Hash_index[index]));
	BigPolyArray tmp2 = evaluator.add(input, evaluator.negate(Hash_index[index + 1]));
	BigPolyArray ans = evaluator.multiply(tmp1, tmp2);

	return ans;
}





/******************************************************************************
 * Function name: AggregateRows()
 * Parameters: ::input:: a BigPolyArray, ::trainingSize:: number of samples
 *
 * Description: sends ::input:: to SGX to sum the contents of its slots; this
 * is the last step of Gradient Descent
 *
 * Return: the sum of the ::input:: slots, as an encrypted BigPolyArray
 ******************************************************************************/
BigPolyArray AggregateRows(BigPolyArray input, int trainingSize)
{
	int idx = 0; // this values should be small than the noise.size() and randomly pick
	Evaluator evaluator(parms);
	input = evaluator.add(input,noise[idx][0]); 

	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	AggregateRows_SGX(eid, buffer, buffer_length, trainingSize, config.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return_ans = evaluator.add(return_ans, evaluator.negate(noise[idx][1]));

	delete[] buffer;	// deleting allocated memory

	return return_ans;
}





/******************************************************************************
* Function name: Simplify_NewSigmoid()
* Parameters: ::input:: a BigPolyArray, ::trainingSize:: number of samples used
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
#ifdef Simplify_NewSigmoid
BigPolyArray NewSigmoid(BigPolyArray input, int trainingSize)
{
	// For One iterator y=0.75*y_initial*x+0.5
	Evaluator evaluator(parms);
	double y_inital = conf.Sigmoid_y_inital;

	BigPolyArray ans = evaluator.multiply(input,Constant);
	ans=DecreaseNoise(ans,trainingSize);

	ans = evaluator.add(ans, Half);

	return ans;
}

#else




/******************************************************************************
 * Function name: ScaleDown()
 * Parameters: 
 * ::input:: a BigPolyArray, ::trainingSize:: number of samples used, 
 * ::precision:: scale factor, to transform floating point values to integers
 *
 * Description: sends ::input:: to SGX to decrypt and rescale
 * Return: the scaled down input, as a BigPolyArray
 ******************************************************************************/
BigPolyArray ScaleDown(BigPolyArray input, int trainingSize,int precision)
{
	int idx = 0; // this values should be small than the noise.size() and randomly pick
	Evaluator evaluator(parms);
	input = evaluator.add(input, noise[idx][0]);

	int buffer_length = 0;
	char * buffer = input.save(buffer_length);

	ScaleDown_SGX(eid, buffer, buffer_length, trainingSize, config.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return_ans = evaluator.add(return_ans, evaluator.negate(noise[idx][0]));

	delete[] buffer;
	return return_ans;

	//Encryptor encryptor(parms, public_key);
	//Decryptor decryptor(parms, secret_key);

	//PolyCRTBuilder crtbuilder(parms);
	//int slot_count = crtbuilder.get_slot_count();
	//vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	//crtbuilder.decompose(decryptor.decrypt(input), values);

	//vector<double> _output(trainingSize);
	//for (int i = 0; i < trainingSize; i++)
	//{
	//	double temp = 0;
	//	if (values[i].to_double() < conf.p_plain_modulus / 2)
	//		temp = (int)values[i].to_double();
	//	else
	//		temp = (int)(values[i].to_double() - conf.p_plain_modulus);
	//	temp = temp / precision;
	//	_output[i] = temp;
	//}

	//for (int i = 0; i < trainingSize; i++)
	//{
	//	if (_output[i] >= 0)
	//		values[i] = (int)Round(_output[i] );
	//	else
	//	{
	//		values[i] = (int)Round(_output[i] + conf.p_plain_modulus);
	//	}
	//}
	//BigPolyArray output;
	//output = encryptor.encrypt(crtbuilder.compose(values));
	//return output;
}





/******************************************************************************
 * Function name: HalfScaleDown()
 * Parameters: 
 * ::input:: a BigPolyArray, ::trainingSize:: number of samples used,
 * ::precision:: scale factor, to transform floating point values to integers
 *
 * Description: sends the ::input:: to SGX, decrypts, and scales its values down
 * by a factor of "precision / 2"
 *
 * Return: the half-scaled down ::input:: as a BigPolyArray
 ******************************************************************************/
BigPolyArray HalfScaleDown(BigPolyArray input, int trainingSize, int precision)
{
	int idx = 0; // this values should be small than the noise.size() and randomly pick
	Evaluator evaluator(parms);
	input = evaluator.add(input, noise[idx][0]);

	int buffer_length = 0;
	char * buffer = input.save(buffer_length);

	HalfScaleDown_SGX(eid, buffer, buffer_length, trainingSize, config.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return_ans = evaluator.add(return_ans, evaluator.negate(noise[idx][0]));

	delete[] buffer;
	return return_ans;

	/*Encryptor encryptor(parms, public_key);
	Decryptor decryptor(parms, secret_key);

	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	crtbuilder.decompose(decryptor.decrypt(input), values);

	vector<double> _output(trainingSize);
	for (int i = 0; i < trainingSize; i++)
	{
		double temp = 0;
		if (values[i].to_double() < conf.p_plain_modulus / 2)
			temp = (int)values[i].to_double();
		else
			temp = (int)(values[i].to_double() - conf.p_plain_modulus);
		temp = temp / precision;
		_output[i] = temp/2;
	}

	for (int i = 0; i < trainingSize; i++)
	{
		if (_output[i] * precision >= 0)
			values[i] = (int)Round(_output[i]);
		else
		{
			int temp = (int)Round(_output[i] );
			values[i] = temp + conf.p_plain_modulus;
		}
	}
	BigPolyArray output;
	output = encryptor.encrypt(crtbuilder.compose(values));
	return output;*/
}





/******************************************************************************
* Function name: compare()
* Parameters: value, a double
*
* Description: 
* Return: 
******************************************************************************/
void compare(BigPolyArray input, int trainingSize)
{
	Evaluator evaluator(parms);
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	int precision = config.precision;
	Decryptor decryptor(parms, secret_key);
	crtbuilder.decompose(decryptor.decrypt(input), values);

	vector<double> temp (trainingSize,0);

	vector<double> y_n(trainingSize,config.Sigmoid_y_inital);

	for (int i = 0; i < config.Sigmoid_itor; i++)
	{
		for (int j = 0; j < trainingSize; j++)
		{
			if (values[j].to_double() < config.p_plain_modulus / 2)
				temp[j] = (int)values[j].to_double();
			else
				temp[j] = (int)(values[j].to_double() - config.p_plain_modulus);
			temp[j] = temp[j] / precision;
			y_n[j] = y_n[j] * (3 - temp[j] * temp[j] * y_n[j] * y_n[j]) / 2;
		}
	}

	vector<double> _output(trainingSize);
	for (int i = 0; i < trainingSize; i++)
	{
		double temp = 0;
		if (values[i].to_double() < config.p_plain_modulus / 2)
			temp = (int)values[i].to_double();
		else
			temp = (int)(values[i].to_double() - config.p_plain_modulus);
		temp = temp / precision;
		_output[i] = 0.5*temp*y_n[i] + 0.5;
		cout << i << ": " << _output[i] << endl;
	}
	for (int i = 0; i < trainingSize; i++)
	{
		if (_output[i] * precision >= 0)
			values[i] = (int)(_output[i] * precision);
		else
		{
			int temp = (int)(_output[i] * precision);
			values[i] = temp + config.p_plain_modulus;
		}
	}
}




/******************************************************************************
 * Function name: NewSigmoid()
 * Parameters: 
 * ::input:: a BigPolyArray, the value to be evaluated
 * ::trainingSize:: number of samples used
 *
 * Description: evaluates the approximated sigmoid (approximation of ISR) over
 * encrypted input
 * Return: output of approximated sigmoid, encrypted as a BigPolyArray
 ******************************************************************************/
BigPolyArray ApproxSigmoid(BigPolyArray input, int trainingSize)
{
	/*
	For more iterator, the output=0.5*x*Yn+0.5
	Yn=Yn-1 * ( 3-x^2* (Yn-1)^2)/2
	*/

	Evaluator evaluator(parms);
	Encryptor encryptor(parms, public_key);
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	int precision = config.precision;

	BigPolyArray y_n = y_0;

#ifdef DEBUG
	Decryptor decryptor(parms, secret_key);
	//crtbuilder.decompose(decryptor.decrypt(input), values);
	//for (size_t i = 0; i < trainingSize; ++i)
	//{
	//	if (values[i].to_double() > conf.p_plain_modulus / 2)
	//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//	else
	//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//}
#endif

	for (int iter = 0; iter < config.Sigmoid_itor; iter++)
	{
		BigPolyArray x_y = evaluator.multiply(y_n, input);
		x_y = ScaleDown(x_y, trainingSize, precision);

		BigPolyArray x_y_2 = evaluator.multiply(x_y, x_y);

#ifdef DEBUG
		//crtbuilder.decompose(decryptor.decrypt(x_y_2), values);
		//for (size_t i = 0; i < trainingSize; ++i)
		//{
		//	if (values[i].to_double() > conf.p_plain_modulus / 2)
		//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
		//	else
		//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
		//}
#endif

		BigPolyArray minus = evaluator.add_plain(evaluator.negate(x_y_2), plain_3);
		minus = ScaleDown(minus, trainingSize, precision);

		y_n = evaluator.multiply(y_n, minus);
		y_n = HalfScaleDown(y_n,trainingSize,precision);
#ifdef DEBUG
		//crtbuilder.decompose(decryptor.decrypt(y_n), values);

		//for (size_t i = 0; i < trainingSize; ++i)
		//{
		//	if (values[i].to_double() > conf.p_plain_modulus / 2)
		//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
		//	else
		//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
		//}
#endif
	}

	BigPolyArray output;
	output = evaluator.multiply(input, y_n);

#ifdef DEBUG
	//crtbuilder.decompose(decryptor.decrypt(output), values);

	//for (size_t i = 0; i < trainingSize; ++i)
	//{
	//	if (values[i].to_double() > conf.p_plain_modulus / 2)
	//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus)  << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//	else
	//		cout << "(" << i << ", " << (values[i].to_double())  << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//}
#endif

	output = evaluator.add_plain(output,one);

#ifdef DEBUG
	//crtbuilder.decompose(decryptor.decrypt(output), values);

	//for (size_t i = 0; i < trainingSize; ++i)
	//{
	//	if (values[i].to_double() > conf.p_plain_modulus / 2)
	//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus)  << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//	else
	//		cout << "(" << i << ", " << (values[i].to_double())  << ")" << ((i != trainingSize - 1) ? ", " : "\n");
	//}
#endif


	output = HalfScaleDown(output,trainingSize,precision);

//#ifdef DEBUG
//	crtbuilder.decompose(decryptor.decrypt(output), values);
//
//	for (size_t i = 0; i < trainingSize; ++i)
//	{
//		if (values[i].to_double() > conf.p_plain_modulus / 2)
//			cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
//		else
//			cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != trainingSize - 1) ? ", " : "\n");
//	}
//#endif

	return output;
}
#endif




// PROBABLY NEED TO REMOVE THIS FUNCTION
/******************************************************************************
* Function name: Round()
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
BigPolyArray sigmod_Hash(BigPolyArray input)
{
	// This part is used to create a SGX buffer, and after we create buffer, we send this buffer to SGX.
	for (int i = 0; i < Hash_index.size()-1; i++)
	{
		BigPolyArray tmp_input;
		tmp_input = HashCiphertext(input,i);
		int buffer_length = 0;
		char *buffer = tmp_input.save(buffer_length);

		foo(eid, buffer, buffer_length);

		int secretIntValue = 0;
		int *secretIntPointer = &secretIntValue;
		check_Index(eid, secretIntPointer);
		if (secretIntValue)
		{
			cout << "return index " << i << endl;
			return Hash_result[i];
		}
		cout << ".";
	}
	cout << "return index " << Hash_result.size()-1 << endl;
	return Hash_result.back();
}




// NEED TO RENAME FUNCTION (AT LEAST REMOVE TYPO)
/******************************************************************************
 * Function name: sigmoid_Hme()
 * Parameters: value, a double
 *
 * Description: rounds the input ::value:: to the nearest whole number
 * Return: a rounded double?
 ******************************************************************************/
BigPolyArray sigmod_Hme(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	sigmod_sgx(eid, buffer, buffer_length, trainingSize,config.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}





/******************************************************************************
 * Function name: TrueSigmoid()
 * Parameters: 
 * ::input:: a double
 *
 * Description: evaluates the true sigmoid function, 1/(1+exp(-x)) at ::input::
 * Return: the output of the sigmoid function, as a double
 ******************************************************************************/
double TrueSigmoid(double input)
{
	return 1 / (1 + exp(-input));
}




/******************************************************************************
* DELETE THIS FUNCTION
******************************************************************************/
void InitialHashTable()
{
	vector<double>hash_range;
	hash_range.push_back(-1000);
	Create_Vector_By_Step(hash_range, -5, 0.5, 5);
	hash_range.push_back(1000);
	for (int i = 0; i < hash_range.size(); i++)
	{
		Hash_index.push_back(Encryption(hash_range[i]));
		Hash_result.push_back(Encryption(TrueSigmoid(hash_range[i])));
	}
}



/******************************************************************************
 * Function name: InitialNoise()
 * Parameters: 
 * ::trainingSize:: number of training samples used, 
 * ::precision:: the scale factor use to transform floating point values to int
 *
 * Description: 
 * Return: none
 ******************************************************************************/
void InitialNoise(int trainingSize, int precision)
{
	// Create the PolyCRTBuilder & initialize parameters
	Encryptor encryptor(parms, public_key);
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigPolyArray> combine(2);

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	for (int num = 0; num < 1; num++)
	{
		int sum = 0;
		for (int i = 0; i < trainingSize; i++)
		{
			double tmp = 0*precision;
			values[i] = int(tmp);
			sum += tmp;
		}
		BigPolyArray _noise = encryptor.encrypt(crtbuilder.compose(values));

		for (int i = 0; i < trainingSize; i++)
		{
			values[i] = sum;
		}
		BigPolyArray _sum = encryptor.encrypt(crtbuilder.compose(values));

		combine[0] = _noise;
		combine[1] = _sum;
		noise.push_back(combine);
	}
	
}




/******************************************************************************
* Function name: InitializeTrainingSet
* Parameters: 
* ::XTrainWBC:: 
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
void InitializeTrainingSet(vector<BigPolyArray>& XTrainWBC, BigPolyArray& yTrainWBC, vector<vector<double>>& plainTextData, vector<double>& plainTextY, int trainingSize, int precision)
{
	// randomly 
	int idx = 0;
	srand(time(NULL));
	for (int i = 0; i < trainingSize; i++)
	{
		idx = (int) GetRandom(0, X.size()-1);
		bool unique = true;
		for (int j = 0; j < trainV.size(); j++) {
			if (idx == trainV[j]) {
				unique = false;
				break;
			}
		}
		if (unique) {
			trainV.push_back(idx); //using this for random pick X
		}
		else {
			i--;
		}
	}
	
	// DEBUGGING
#ifdef DEBUG
	cout << "Dimens of trainV global vector: " << trainV.size() << endl;
	cout << "Dimens of X: " << X.size() << " and " << X[0].size() << endl;
#endif

	Encryptor encryptor(parms, public_key);
	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// Create a vector for first column in X
	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = 1;
	}
	BigPoly plain_composed_poly = crtbuilder.compose(values);
	BigPolyArray encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
	XTrainWBC[0] = encrypted_composed_poly;

	// Create CTX for other column in X
	for (int i = 0; i < X[0].size() ; i++)
	{
		for (int j = 0; j < trainV.size(); j++)
		{
			values[j] = X[trainV[j]][i];
			plainTextData[j][i+1] = X[trainV[j]][i];
		}
		plain_composed_poly = crtbuilder.compose(values);
		encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
		XTrainWBC[i + 1] = encrypted_composed_poly;
	}

	// Create CTX for Y
	for (int i = 0; i < trainV.size(); i++)
	{
		values[i] = Y[trainV[i]]*precision;
		plainTextY[i] = Y[trainV[i]];
	}
	plain_composed_poly = crtbuilder.compose(values);
	yTrainWBC = encryptor.encrypt(plain_composed_poly);


	// Initial some values for New SigMoid
	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = (int)(precision*precision);
	}
	one = crtbuilder.compose(values);

	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = config.Sigmoid_y_inital*config.precision;
	}
	y_0 = encryptor.encrypt(crtbuilder.compose(values));

	// PRINT CIPHERTEXT SIZE TO CONSOLE
	//int size = 0;
	//y_0.save(size);
	//cout << size << endl;


	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = 3 * precision*precision;
	}
	plain_3 = crtbuilder.compose(values);
}





/******************************************************************************
* Function name: InitializeTestSet
* Parameters: value, a double
*
* Description: rounds the input ::value:: to the nearest whole number
* Return: a rounded double?
******************************************************************************/
void InitializeTestSet(vector<vector<double>>& XTest, vector<double>& yTest, int testSize, int trainingSize)
{
	int idx = 0;
	for (int i = 0; i < testSize; i++)
	{
		idx = (int)GetRandom(0, X.size()-1);
		bool unique = true;
		for (int j = 0; j < testV.size(); j++) {
			if (idx == testV[j]) {
				unique = false;
				break;
			}
			else if (find(trainV.begin(), trainV.end(), idx) != trainV.end()) {		
				unique = false;
				break;
			}
		}
		if (unique) {
			testV.push_back(idx);
			//			XTrainWBC[i][0] = Encryption(1.0); // ADD '1' AS FIRST FEATURE VALUE FOR INTERCEPT TERM
			for (int k = 0; k < X[0].size(); k++) {
				XTest[i][k + 1] = X[idx][k];
			}
			yTest[i] = Y[idx];
			//cout << i + 1 << "Test sample " << i << " encrypted" << endl;
		}
		else {
			i--;
		}
	}
	
}



/******************************************************************************
 * Function name: InitializeWeights()
 * Parameters: value, a double
 *
 * Description: rounds the input ::value:: to the nearest whole number
 * Return: a rounded double?
 ******************************************************************************/
void InitializeWeights(vector<double>& plaintextWeights, vector<BigPolyArray>& encryptedWeights, int feature, int trainingSize, int precision)
{
	// Create randomly initialized weights (plaintext) - then encrypt
	srand(time(NULL));

	Encryptor encryptor(parms, public_key);
	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// precision is the SCALING FACTOR (B)
	for (int i = 0; i < feature; i++)
	{
		//plaintextWeights[i] = rand() / double(RAND_MAX);// using this for random pick weight
		plaintextWeights[i] = GetRandom(0, 1);
		for (int j = 0; j < trainingSize; j++)
		{
			values[j] = plaintextWeights[i] * precision;
		}
		BigPoly plain_coeff_poly = crtbuilder.compose(values);
		encryptedWeights[i] = encryptor.encrypt(plain_coeff_poly);
	}
}

void InitialConfigure(MakeConfigure mconf)
{
	config.Sigmoid_itor = mconf.ToInt(mconf.FindConfigure("Sigmoid_itor"));
	config.Sigmoid_y_inital = mconf.ToDouble(mconf.FindConfigure("Sigmoid_y_inital"));
	config.learningRate = mconf.ToDouble(mconf.FindConfigure("learningRate"));
	config.numEpochs = mconf.ToInt(mconf.FindConfigure("runs"));
	config.maxItor = mconf.ToDVector(mconf.FindConfigure("maxItor"));
	config.psamples = mconf.ToDVector(mconf.FindConfigure("psamples"));
	config.p_poly_modulus = mconf.FindConfigure("p_poly_modulus");
	config.p_coeff_modulus = mconf.ToInt(mconf.FindConfigure("p_coeff_modulus"));
	config.encoder_conf = mconf.ToIVector(mconf.FindConfigure("encoder_conf"));
	config.p_plain_modulus = mconf.ToInt(mconf.FindConfigure("p_plain_modulus"));
	config.precision = mconf.ToInt(mconf.FindConfigure("precision"));

	char* buffer = mconf.ReturnConf();
	MakeConfigure_SGX(eid, buffer, 500);
}



/******************************************************************************
 * Function name: EncryptedLogisticRegression
 * Parameters: 
 *
 * Description: 
 *
 * Return: encrypted trained model parameters (weights, a vector<BigPolyArray>)
******************************************************************************/
// TRYING THIS APPROXIMATED SIGMOID: 0.5x*( 0.02*(3-x2*0.02^2))/2+0.5 = 0.005x * (3 - 0.0004*x^2) + 0.5
//-------------------------< Logistic Regression Weight >-------------------------------------------
vector<BigPolyArray> EncryptedLogisticRegression(
	vector<BigPolyArray>& XTrain, BigPolyArray& yTrain, vector<BigPolyArray>& w0, int maxEpochs,
	int numTrainingSamples, double learningRate,int nFeatures)
{
	Evaluator evaluator(parms);
//	BigPoly encLearningRate = Encoder(learningRate);
#ifdef DEBUG
	Decryptor decryptor(parms, secret_key);
#endif // DEBUG

	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	vector<float> averageEpochTime(maxEpochs, 0);

#ifdef SHOWRESULT
#endif
	for (int epoch = 0; epoch < maxEpochs; epoch++)
	{

		// TIME EACH EPOCH:
		double duration;
		std::clock_t startEpoch;
		startEpoch = std::clock();

		//cout << "epoch :" << epoch << endl;
		vector<BigPolyArray> wUpdate = w0;
		BigPolyArray inputToSigmoid = Encryption(0);

		for (int i = 0; i < nFeatures; i++)
		{
			inputToSigmoid = evaluator.add(evaluator.multiply(XTrain[i], w0[i]), inputToSigmoid); // CHECKED THIS OUTPUT
		}
#ifdef DEBUG
		BigPoly ans;
		//ans = decryptor.decrypt(inputToSigmoid);
		//crtbuilder.decompose(ans, values);
		//cout << "The decrypted input to sigmoid: " << endl;
		//for (size_t i = 0; i < numTrainingSamples; ++i)
		//{
		//	if (values[i].to_double() > conf.p_plain_modulus / 2)
		//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
		//	else
		//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
		//}
#endif

		BigPolyArray outputOfSigmoid;
		outputOfSigmoid = ApproxSigmoid(inputToSigmoid, numTrainingSamples); // CHECKED THIS OUTPUT

#ifdef DEBUG
	//ans = decryptor.decrypt(outputOfSigmoid);
	//crtbuilder.decompose(ans, values);
	//cout << "Sigmoid output (scaled and as a double): " << endl;
	//for (size_t i = 0; i < numTrainingSamples; ++i)
	//{
	//	if (values[i].to_double() > conf.p_plain_modulus / 2)
	//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
	//	else
	//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
	//}
#endif

		BigPolyArray error;
		error = evaluator.add(yTrain, evaluator.negate(outputOfSigmoid)); // CORRECT - CHECKED THIS

#ifdef DEBUG
	//ans = decryptor.decrypt(error);
	//crtbuilder.decompose(ans, values);
	//cout << "Errors between scaled sigmoid output and true 'y' value: " << endl;
	//for (size_t i = 0; i < numTrainingSamples; ++i)
	//{
	//	if (values[i].to_double() > conf.p_plain_modulus / 2)
	//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
	//	else
	//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
	//}
#endif

		//cout << "Weight update value: " << endl;
		// ERROR HAS TO BE HERE
		// tmp is the contribution of weight for feature 'i' for all n samples (with respect to feature 'i')
		for (int i = 0; i < nFeatures; i++)
		{
			BigPolyArray tmp = evaluator.multiply(error, XTrain[i]);
			tmp = AggregateRows(tmp, numTrainingSamples);
			wUpdate[i] = tmp;

#ifdef DEBUG
			//ans = decryptor.decrypt(tmp);
			//crtbuilder.decompose(ans, values);
			//for (size_t i = 0; i < 1; ++i)
			//{
			//	if (values[i].to_double() > conf.p_plain_modulus / 2)
			//		cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != 1 - 1) ? ", " : "\n");
			//	else
			//		cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != 1 - 1) ? ", " : "\n");
			//}
#endif
		}
		//cout << "Weight value after updating : " << endl;

		for (int i = 0; i < nFeatures; i++)
		{
			w0[i] = evaluator.add(w0[i], wUpdate[i]);
#ifdef  DEBUG
			ans = decryptor.decrypt(w0[i]);
			crtbuilder.decompose(ans, values);
			//// PRINT UPDATED WEIGHT VALUES EVERY 10 EPOCHS
			//if (epoch % 10 == 0 && epoch != maxEpochs - 1)
			//{
			//	cout << "Updated weights at epoch: " << epoch << endl;
			//	for (size_t i = 0; i < 1; ++i)
			//	{
			//		if (values[i].to_double() > conf.p_plain_modulus / 2)
			//			cout << "(" << i << ", " << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ")" << ((i != 1 - 1) ? ", " : "\n");
			//		else
			//			cout << "(" << i << ", " << (values[i].to_double()) / conf.precision << ")" << ((i != 1 - 1) ? ", " : "\n");
			//	}
			//}

			// PRINTING THE FINAL TRAINED WEIGHTS
			//if (epoch == maxEpochs - 1)
			//{
			//	cout << "Final trained weights: " << endl;
			//	ans = decryptor.decrypt(w0[i]);
			//	crtbuilder.decompose(ans, values);
			//	for (size_t i = 0; i < 1; ++i)
			//	{
			//		if (values[i].to_double() > conf.p_plain_modulus / 2)
			//			cout << (values[i].to_double() - conf.p_plain_modulus) / conf.precision << ((i != 1 - 1) ? ", " : "\n");
			//		else
			//			cout << (values[i].to_double()) / conf.precision << ((i != 1 - 1) ? ", " : "\n");
			//	}
			//}

#endif // ! DEBUG
		}

		// END epoch time & print to console
		duration = (std::clock() - startEpoch) / (double)CLOCKS_PER_SEC;
		std::cout << "Epoch " << epoch << " time: " << duration / 60 << '\n';
		averageEpochTime[epoch] = (duration / 60);

	}
	// PRINT AVERAGE TIME PER EPOCH
	cout << "Average TIME PER EPOCH: " << (accumulate(averageEpochTime.begin(), averageEpochTime.end(), 0.0) / maxEpochs) << endl;
	return w0;
}





/******************************************************************************
 * Function name: Predict()
 * Parameters:
 *
 * Description: decrypted in input (encrypted) weight vector, ::w0::, and 
 * computes the predictions of the given Test Set using these weights; 
 *
 * Return: returns computed predictions in plaintext (vector<double>)
 ******************************************************************************/
#if defined (SHOWRESULT)|| defined(DEBUG)
vector<double> Predict(const vector<vector<double>>& XTest, const vector<double>& YTest,
	const vector<BigPolyArray>& w0, int numFeatures, int testSize, int precision)
{
	/*char skb[MAX_BUF_LEN];*/
	// INITIALIZE ON HEAP 
	char * skb = new char[MAX_BUF_LEN];
	get_secret_key(eid, skb, MAX_BUF_LEN);
	secret_key.load(skb);

	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));


	vector<double> weight;
	for (int i = 0; i < w0.size(); i++)
	{
		BigPoly ans = EncryptToEncode(w0[i]);
		crtbuilder.decompose(ans, values);

		// here - CONVERT POTENTIALLY NEGATIVE VALUES TO CORRECT VALUE
		double decryptedWeight = 0;
		if (values[0].to_double() > config.p_plain_modulus / 2) {
			decryptedWeight = (values[0].to_double() - config.p_plain_modulus) / precision;
		}
		else {
			decryptedWeight = values[0].to_double() / precision;
		}
		weight.push_back(decryptedWeight);
	}

	vector<double> predictions;
	vector<double> mean_abs_error;
	for (int i = 0; i < testSize; i++)
	{
		double inputToSigmoid = 0;
		for (int j = 0; j < numFeatures + 1; j++)
		{
			inputToSigmoid = XTest[i][j] * weight[j] + inputToSigmoid;
		}
		inputToSigmoid = TrueSigmoid(inputToSigmoid);
		//cout << "sigmoid output (prediction): " << inputToSigmoid << endl;
		//cout  << tmpmulti << endl;
		predictions.push_back(inputToSigmoid);
		if (inputToSigmoid - YTest[i] < 0) 
		{
			mean_abs_error.push_back(YTest[i] - inputToSigmoid);
		}
		else 
		{
			mean_abs_error.push_back(inputToSigmoid - YTest[i]);
		}
	}

	cout << "Predictions on test set" << endl;
	cout << "pred_array = np.array([";
	double mae = 0;
	for (int i = 0; i < predictions.size(); i++) {
		//cout << "The prediction for the " << i+1 << "th example = " << predictions[i] << " actual Y = " << YTest[i] << endl;
		cout << predictions[i] << ", ";
		mae += mean_abs_error[i];
	}
	cout << "])" << endl;
	cout << "actual_array = np.array([";
	for (int i = 0; i < YTest.size(); i++) {
		cout << YTest[i] << ", ";
	}
	cout << "]);" << endl;
	mae = mae / mean_abs_error.size();
	cout << "The mean absolute error = " << mae << endl;
	delete skb;
	return predictions;
}




/******************************************************************************
 * Function name: AUC()
 * Parameters: ::predictions:: a vector<double> of predictions produced by the
 * Predict() function; ::yTest:: a vector<double> of true target/class values 
 *
 * Description: computes the AUROC and returns the single value as an accuracy
 * metric
 *
 * Return: returns the AUROC, a double
 ******************************************************************************/
double AUC(vector<double> predictions, vector<double>& yTest)
{
	int nTarget=0;
	int nBackground=0;

	for (int i = 0; i < yTest.size(); i++)
	{
		if (yTest[i] == 1)
			nTarget++;
		if (yTest[i] == 0)
			nBackground++;
	}

	vector<double> _p;
	_p = predictions;
	_p.push_back(10);
	sort(_p.begin(), _p.end());

	vector<vector<double>> map(_p.size(), vector<double>(2,0));
	for (int i = 0; i < _p.size(); i++)
		map[i][0] = _p[i];

	double count = 1;
	double sum = 0;
	for (int i = 0; i < map.size()-1; i++)
	{
		if (map[i][0] != map[i + 1][0])
		{
			sum = 0;
			for (int j = i; j >=i-count+1; j--)
				sum += j+1;
			for (int j = i; j >= i - count + 1; j--)
				map[j][1] = sum / count;
			count = 1;
		}
		else
			count++;
	}

	double rSum = 0;
	for (int i = 0; i < predictions.size(); i++)
	{
		if (yTest[i] == 1)
		{
			for (int j = 0; j < map.size() - 1; j++)
			{
				if (map[j][0] == predictions[i])
				{
					rSum += map[j][1];
					break;
				}
			}
		}
	}
		
	double AUC = 0.0;
	AUC = (rSum - (nTarget*nTarget + nTarget) / 2) / (nTarget*nBackground);
	cout << AUC << endl;
	return AUC;

}



/******************************************************************************
* Function name: PlaintextLRTest()
* Parameters:
*
* Description: 
*
* Return: 
******************************************************************************/
vector<double> PlaintextLRTest(vector<double> _w0, double learningRate, int trainingSize, int testSize, 
	int numFeatures, vector<vector<double>> XTest, vector<double> YTest)
{
	//vector<vector<double>> _X(trainingSize,vector<double>(X[0].size()+1,1.0));
	//for (int i = 0; i < trainingSize; i++)
	//	for (int j = 1; j < X[0].size()+1; j++)
	//		_X[i][j]=X[trainV[i]][j-1];

	// LOOP THROUGH ALL DATA *maxEpochs* NUMBER OF TIMES
	for (int epoch = 0; epoch < orderOfRandomTraining.size(); epoch++) {

		for (int i = 0; i < trainingSize; i++)
		{
			vector<double> _tw(_w0.size(), 0.0);
			double inputToSigmoid = 0;
			//		cout << "Plaintext: value of XTrain, weight and inputToSigmoid:" << endl;
			for (int j = 0; j < _tw.size(); j++)
			{
				inputToSigmoid = XTest[orderOfRandomTraining[epoch][i]] [j] * _w0[j] + inputToSigmoid;
				cout << XTest[orderOfRandomTraining[epoch][i]][j] << "    " << _w0[j] << "    " << inputToSigmoid << endl;
			}
			//cout << "Plaintext: value of sigmoid(inputToSigmoid):" << endl;
			for (int k = 0; k < _w0.size(); k++)
			{
				double error = 0;
				double gradient = 0;
				double weightUpdateVal = 0;

				double y_inital = config.Sigmoid_y_inital;
				double y_after = 0.75*y_inital;
				double output = inputToSigmoid*y_after + 0.5;
				//			cout << "Plaintext output: " << output << endl;
				error = output - YTest[orderOfRandomTraining[epoch][i]];
				cout << "Error on plaintext data for epoch " << epoch << " : " << error << endl;
				gradient = error * XTest[orderOfRandomTraining[epoch][i]][k];
				weightUpdateVal = learningRate * gradient;
				_tw[k] = weightUpdateVal;
			}
			for (int i = 0; i < _w0.size(); i++)
				_w0[i] = _w0[i] - _tw[i];
		}
	}

	//int nSamples = XTest.row;
	//Matrix<double> _XT(nSamples, 1 + XTest.col);
	//_XT.Set_Default_Value(1.0);
	//for (int i = 0; i < _XT.row; i++) {
	//	for (int j = 1; j < _XT.col; j++)
	//		_XT.assign(i, j, XTest.at(i, j - 1));
	//}

	// PREDICTION STEP
	vector<double> _probability;
	//cout << " The input of sigmoid is: " << endl;
	for (int i = 0; i < testSize; i++)
	{
		double inputToSigmoid = 0;
		for (int j = 0; j < 1 + numFeatures; j++)
		{
			inputToSigmoid = XTest[i][j] * _w0[j] + inputToSigmoid;
		}
		//cout  << tmpmulti << endl;
		_probability.push_back(TrueSigmoid(inputToSigmoid));
	}
//	cout << endl;
	//cout << "The resulting weights on plaintext data: " << endl;
	//for (int i = 0; i < _w0.row; i++)
	//	cout << _w0.at(i, 0) << endl;
	//cout << endl;

	AUC(_probability, YTest);

	return _w0;
}
#endif




/******************************************************************************
 * Function name: main()
 * Parameters:?
 *
 * Description: initializes the ENCLAVE, Homomorphic Encryption parameters;
 * 
 *
 * Result:
 ******************************************************************************/
#define TEST_LOGISTIC_REGRESSION
#ifdef TEST_LOGISTIC_REGRESSION
void main()
{
	std::clock_t startInit;
	double initTime;
	startInit = std::clock();
	cout << "Initialization of HME parameters & enclave: " << endl;
	// Create sgx enclave
	sgx_status_t        ret = SGX_SUCCESS;
	sgx_launch_token_t  token = { 0 };
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
		return;

	// Initizal the Configure
	MakeConfigure mconf;
	mconf.Initalize();
	InitialConfigure(mconf);

	// Create encryption parameters
	parms.poly_modulus() = config.p_poly_modulus;
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(config.p_coeff_modulus);
	parms.plain_modulus() = config.p_plain_modulus;

	// Generate keys.
	cout << "... Generating keys ..." << endl;
	generate_key_sgx(eid);
	/*char public_key_buffer[MAX_BUF_LEN];*/
	char * public_key_buffer = new char[MAX_BUF_LEN];
	get_public_key(eid, public_key_buffer, MAX_BUF_LEN);
	public_key.load(public_key_buffer);
	cout << "... Public key generation complete ..." << endl;


#ifdef DEBUG
	//-------------< test for some function and feature >-------------------------------------------------
	cout << "This is a test for sigmoid function and sgx" << endl;
	char * secret_key_buffer = new char[MAX_BUF_LEN];
	get_secret_key(eid, secret_key_buffer, MAX_BUF_LEN);
	secret_key.load(secret_key_buffer);
	cout << "... secret key generation complete" << endl;
#endif

	// HYPERPARAMETERS - these are printed to console and may be changed here
	int precision = config.precision;
	int trainingSize = (X.size() * 0.79);
	int testSize = (X.size() * 0.19);
	int numFeatures = X[0].size();
	double learnRate = config.learningRate; // DOES NOT REFLECT ACTUAL LEARNING RATE - SEE SealEnclaveTest.cpp
	int numEpochs = config.numEpochs;
	InitialNoise(trainingSize,precision);

	initTime = (std::clock() - startInit) / (double)CLOCKS_PER_SEC;
	std::cout << "Initialization time: " << initTime / 60 << '\n';

	const int NUM_TRIALS = 10;
	// initialze vector to store testAUCs
	vector<double> testAUC(NUM_TRIALS, 0);
	vector<double> trainingTime(NUM_TRIALS, 0);
	for (int currTrial = 0; currTrial < NUM_TRIALS; currTrial++) {

		trainV.clear();
		orderOfRandomTraining.clear();
		testV.clear();

		cout << "**********************************************************************************************" << endl;
		cout << "Trial " << currTrial + 1 << " | training size: " << trainingSize << " | test size: " << testSize << endl;
		cout << "Num. features: " << numFeatures << " | Learning rate: " << learnRate << " | Num Epochs: " << numEpochs << endl;
		vector<BigPolyArray> XTrainWBC(numFeatures + 1);
		BigPolyArray yTrainWBC;
		vector<vector<double>> trainingDataForTesting(trainingSize, vector<double>(numFeatures + 1, 0.0));
		vector<double> trainingYForTesting(trainingSize, 1);
		InitializeTrainingSet(XTrainWBC, yTrainWBC, trainingDataForTesting, trainingYForTesting, trainingSize, precision);

		vector<vector<double>> xTest(testSize, vector<double>(numFeatures + 1, 1));
		vector<double> yTest(testSize, 0);
		InitializeTestSet(xTest, yTest, testSize, trainingSize);
		cout << " Complete Matrix" << endl;

		// RANDOMLY INITIALIZE WEIGHTS 
		vector<double> plainWeights(numFeatures + 1, 1);
		vector<BigPolyArray> encryptWeights(numFeatures + 1);
		InitializeWeights(plainWeights, encryptWeights, numFeatures + 1, trainingSize, precision);
		
		// TIME THE LR TRAINING & TESTING
		std::clock_t start;
		double trainingDuration;
		start = std::clock();

		encryptWeights = EncryptedLogisticRegression(XTrainWBC, yTrainWBC, encryptWeights, numEpochs, trainingSize, learnRate, numFeatures + 1);

		trainingDuration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
		trainingTime[currTrial] = (trainingDuration / 60);
		std::cout << "SecureLR model training time: " << (trainingDuration / 60) << endl;

#ifdef SHOWRESULT
		cout << "Training set AUC: " << endl;
		AUC(Predict(trainingDataForTesting, trainingYForTesting, encryptWeights, numFeatures, trainingSize, precision), trainingYForTesting);
		cout << endl;
		cout << "Test set AUC: " << endl;
		testAUC[currTrial] = AUC(Predict(xTest, yTest, encryptWeights, numFeatures, testSize, precision), yTest);
		cout << endl;

#endif
		cout << "**********************************************************************************************" << endl;

	}
	cout << "Average model training time: " << (accumulate(trainingTime.begin(), trainingTime.end(), 0.0) / NUM_TRIALS) << endl;
	cout << "Average TEST AUC: " << (std::accumulate(testAUC.begin(), testAUC.end(), 0.0) / NUM_TRIALS) << endl;
	cout << endl;
	cout << "... All is completed ..." << endl;

	// Destroy the Enclave
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		cout << "destroy error" << endl;
	cout << "... Destroy the enclave successfully ..." << endl;

	// deallocate memory on the heap!
	delete public_key_buffer;
	delete secret_key_buffer;
	system("pause");
}

#endif

