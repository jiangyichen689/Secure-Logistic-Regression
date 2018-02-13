#include "SealEnclaveTest_t.h"

#include "sgx_trts.h"

#include <string.h>
#include <sstream>
#include <cstring>
#include <chrono>
#include <vector>
#include "../SEAL/seal.h"

using namespace std;
using namespace seal;

EncryptionParameters parms_sgx;
BigPoly secret_key_sgx;
BigPolyArray public_key;
double decrypted_number;

static struct configure_SGX
{
	string p_poly_modulus;
	int p_coeff_modulus;
	vector<int> encoder_conf;
	int p_plain_modulus;
	double learningRate;
}conf_SGX;

int check_Index()
{
	int flag = 0;
	if (decrypted_number > 0)
		flag = 0;
	else
		flag = 1;
	return flag;
}

void sigmod_sgx(char* buffer, size_t len, int trainingSize, int precision)
{	
	
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);
	BigPolyArray input;
	input.load(buffer);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	BigPoly ans = decryptor.decrypt(input);
	crtbuilder.decompose(ans, values);

	double result = 0;
	for (int i = 0; i < trainingSize; i++)
	{
		if (values[i].to_double() > conf_SGX.p_plain_modulus / 2) 
		{
			result = (values[i].to_double() - conf_SGX.p_plain_modulus) / precision;
		} 
		else 
		{
			result = (values[i].to_double() / precision);
		}
		result = 1 / (1 + exp(-result));
		values[i] = (uint64_t) (result  * precision);
	}

	BigPoly plain_coeff_poly = crtbuilder.compose(values);
	BigPolyArray output = encryptor.encrypt(plain_coeff_poly);
	
	int length = 0;
	char* tmp_buf = output.save(length);

	memcpy(buffer,tmp_buf,length);
	delete[] tmp_buf;
}

void foo(char* buf, size_t len)
{
	FractionalEncoder encoder(parms_sgx.plain_modulus(), parms_sgx.poly_modulus(), 
		conf_SGX.encoder_conf[0], conf_SGX.encoder_conf[1], conf_SGX.encoder_conf[2]);
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	Evaluator evaluator(parms_sgx);
	BigPoly encoded_number;
	BigPolyArray encrypted_rational;
	BigPoly plain_result;

	encrypted_rational.load(buf);
	plain_result = decryptor.decrypt(encrypted_rational);
	double result = encoder.decode(plain_result);
	decrypted_number = result;
}

void DecreaseNoise_SGX(char* buf, size_t len,int trainingSize, double y_initial)
{
	// Create all the tool
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	BigPolyArray input;
	input.load(buf);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	BigPoly ans = decryptor.decrypt(input);
	crtbuilder.decompose(ans, values);

	double sum = 0;
	for (int i = 0; i < trainingSize; i++)
	{
		if (values[i].to_double() < conf_SGX.p_plain_modulus / 2)
			values[i] = (int)(values[i].to_double() * y_initial*0.01);
		else
			values[i] = (int)((values[i].to_double()-conf_SGX.p_plain_modulus) * y_initial*0.01);
	}

	BigPoly plain_coeff_poly = crtbuilder.compose(values);
	BigPolyArray output = encryptor.encrypt(plain_coeff_poly);

	int length = 0;
	char* tmp_buf = output.save(length);
	memcpy(buf, tmp_buf, length);
	delete[] tmp_buf;

}

// ********************** TODO: CURRENTLY DEBUGGING *****************
void AggregateRows_SGX(char* buf, size_t len, int trainingSize, int precision)
{
	// Create all the tool
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	BigPolyArray input;
	input.load(buf);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	BigPoly ans = decryptor.decrypt(input);
	crtbuilder.decompose(ans, values);

	double sum = 0;
	for (int i = 0; i < trainingSize; i++)
	{
		if (values[i].to_double() > conf_SGX.p_plain_modulus / 2)
			sum += (values[i].to_double() - conf_SGX.p_plain_modulus);
		else
			sum += (values[i].to_double());
	}

	if (sum < 0)
	{
		sum = sum*conf_SGX.learningRate;
		sum += conf_SGX.p_plain_modulus;
	}
	else
	{
		sum = sum * conf_SGX.learningRate;
	}

	uint64_t _sum = (uint64_t)sum;

	// changed cast from double --> int to double --> uint64_t
	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = _sum;
	}

	BigPoly plain_coeff_poly = crtbuilder.compose(values);
	BigPolyArray output = encryptor.encrypt(plain_coeff_poly);

	int length = 0;
	char* tmp_buf = output.save(length);
	memcpy(buf, tmp_buf, length);
	delete[] tmp_buf;
}


// ROUND DOWN/UP value
double Round_SGX(double value)
{
	double round_val = (value * pow(10, 0)) / pow(10, 0);
	round_val = (round_val - floor(round_val) >= 0.5 ? floor(round_val) + 1 : floor(round_val));
	return round_val;
}

// Scale down "buf" by precision / 2
void HalfScaleDown_SGX(char* buf, size_t len, int trainingSize, int precision)
{
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	// load the buffer into "input"
	BigPolyArray input;
	input.load(buf);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	crtbuilder.decompose(decryptor.decrypt(input), values);

	vector<double> _output(trainingSize);
	for (int i = 0; i < trainingSize; i++)
	{
		double temp = 0;
		if (values[i].to_double() < conf_SGX.p_plain_modulus / 2)
			temp = (int)values[i].to_double();
		else
			temp = (int)(values[i].to_double() - conf_SGX.p_plain_modulus);
		// multiply by the respective coefficient in the approx_sigmoid
		temp = temp / precision;
		_output[i] = temp / 2;
	}

	for (int i = 0; i < trainingSize; i++)
	{
		if (_output[i] >= 0)
			values[i] = (int)Round_SGX(_output[i]);
		else
		{
			values[i] = (int)Round_SGX(_output[i] + conf_SGX.p_plain_modulus);
		}
	}

	BigPolyArray output;
	output = encryptor.encrypt(crtbuilder.compose(values));
	int length = 0;
	char * tmp_buf = output.save(length);
	memcpy(buf, tmp_buf, length);
	delete[] tmp_buf;

}


// Scale down "buf" by factor of "precision"
void ScaleDown_SGX(char* buf, size_t len, int trainingSize, int precision)
{
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	// load the buffer into "input"
	BigPolyArray input;
	input.load(buf);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	crtbuilder.decompose(decryptor.decrypt(input), values);

	vector<double> _output(trainingSize);
	for (int i = 0; i < trainingSize; i++)
	{
		double temp = 0;
		if (values[i].to_double() < conf_SGX.p_plain_modulus / 2)
			temp = (int)values[i].to_double();
		else
			temp = (int)(values[i].to_double() - conf_SGX.p_plain_modulus);
		// multiply by the respective coefficient in the approx_sigmoid
		temp = temp / precision;
		_output[i] = temp;
	}


	// return round(value * pow(10, n)) / pow(10, n);
	// (x - floor(x) >= 0.5 ? floor(x) + 1 : floor(x))
	for (int i = 0; i < trainingSize; i++)
	{
		if (_output[i] >= 0)
			values[i] = (int)Round_SGX(_output[i]);
		else
		{
			values[i] = (int)Round_SGX(_output[i] + conf_SGX.p_plain_modulus);
		}
	}

	BigPolyArray output;
	output = encryptor.encrypt(crtbuilder.compose(values));
	int length = 0;
	char * tmp_buf = output.save(length);
	memcpy(buf, tmp_buf, length);
	delete[] tmp_buf;
}


//----------------------------< operation for keys >-----------------------------------------
void generate_key_sgx()
{
	parms_sgx.poly_modulus() = conf_SGX.p_poly_modulus;
	parms_sgx.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(conf_SGX.p_coeff_modulus);
	parms_sgx.plain_modulus() = conf_SGX.p_plain_modulus;

	//generate the public_key and secret_key;
	KeyGenerator generator(parms_sgx);
	generator.generate();
	BigPolyArray tmp_public_key = generator.public_key();
	BigPoly tmp_secret_key_sgx = generator.secret_key();

	// Store public_key and secret_key in enclave
	int buffer_size = 0;
	char* tmp_s_k_b = tmp_secret_key_sgx.save(buffer_size);
	secret_key_sgx.load(tmp_s_k_b);

	buffer_size = 0;
	char* tmp_p_k_b = tmp_public_key.save(buffer_size);
	public_key.load(tmp_p_k_b);

	delete[] tmp_s_k_b;
	delete[] tmp_p_k_b;
}

void get_public_key(char* public_key_buffer,size_t len)
{
	int buffer_size = 0;
	char* tmp_p_k_b = public_key.save(buffer_size);
	memcpy(public_key_buffer, tmp_p_k_b, buffer_size);	
	delete[] tmp_p_k_b;
}

void get_secret_key(char* secret_key_buffer,size_t len)
{
	int buffer_size = 0;
	char* tmp_s_k_b = secret_key_sgx.save(buffer_size);
	memcpy(secret_key_buffer, tmp_s_k_b, buffer_size);
	delete[] tmp_s_k_b;
}


// Initial the Configure in the SGX
string FindConfigure(string input,char* ConfigureBuffer)
{
	string ans;
	string tCon = ConfigureBuffer;
	string temp;

	for (int i = 0; i < 500; i++)
	{
		if (ConfigureBuffer[i] == input[0])
		{
			temp = tCon.substr(i, input.length());
			if (temp == input)
			{
				int count = 1;
				i += input.length();
				while (ConfigureBuffer[i] != '=')
					i++;
				while (ConfigureBuffer[i + count] != '#')
					count++;
				ans = tCon.substr(i + 1, count - 1);
				break;
			}
		}
		else
		{
			while (ConfigureBuffer[i] != '#')
				i++;
		}
	}

	return ans;
}

int ToInt(string input)
{
	int value = atoi(input.c_str());
	return value;
}

vector<int> ToIVector(string input)
{
	vector<int> ans;
	int position = 0;
	for (int i = 0; i < input.length(); i++)
	{
		if (input[i] == ';')
		{
			string temp = input.substr(position, i - position);
			ans.push_back(ToInt(temp));
			position = i + 1;
		}
		if (i == input.length() - 1)
		{
			string temp = input.substr(position, i - position + 1);
			ans.push_back(ToInt(temp));
		}
	}
	return ans;
}

double ToDouble(string input)
{
	string::size_type sz;
	double ans = stod(input, &sz);
	return ans;
}

void MakeConfigure_SGX(char* ConfigureBuffer, size_t len)
{
	conf_SGX.encoder_conf=ToIVector(FindConfigure("encoder_conf",ConfigureBuffer));
	conf_SGX.p_poly_modulus = FindConfigure("p_poly_modulus", ConfigureBuffer);
	conf_SGX.p_coeff_modulus = ToInt(FindConfigure("p_coeff_modulus", ConfigureBuffer));
	conf_SGX.p_plain_modulus = ToInt(FindConfigure("p_plain_modulus", ConfigureBuffer));
	conf_SGX.learningRate = ToDouble(FindConfigure("learningRate", ConfigureBuffer));
}
