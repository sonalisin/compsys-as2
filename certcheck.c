/**
    Computer Systems Assignment 2
    Student ID: 931025
    Author: Sonali Singh
**/

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>


/*
  Function declarations
*/

//Open the certificate read from the .csv file
void open_cert(char * path, char * url);
//Check date validity
int check_date(X509 * cert, BIO * c);
//Output the text to output.csv
void output_string(char * path, char * url, int valid);
//Checks if url matches Common Name
int matches_common_name(char *url, X509 *cert);
//Returns Valid or Invalid if all criteria is not met
int validity(int date, int host, int key_length, int basic_con);
//Checks if the url matches the SAN
int matches_san(char * url, X509 *cert);
//Checks the RSA key length of certificate
int check_key_length(X509 * cert);
//Check the basic constraints and key usage
int check_basic_constraints(X509 * cert);
//Get an extension from a certificate
char* get_extension(X509 * cert, X509_EXTENSION *ex);
//Runs through all of the certificate checks
void write_to_output(X509 * cert, BIO * certificate_bio, char * url, char * path);

int main(int argc, char **argv)
{
    int buf_size = 1024;
    char buffer[buf_size+1];
    char * path = NULL;
    char * url = NULL;

  // If there are not enough arguments to run the program, exit
    if(argc != 2){
      perror("Incorrect number of arguments.\n");
       return EXIT_FAILURE;
    }

    // Opening the output csv file to write to
    FILE *fw = fopen("output.csv", "w");
    if(!fw){
      perror("Unable to open write file.\n");
      return EXIT_FAILURE;
    }

    // Open the input .csv file, and exit the program if unable to open
    FILE *fp = fopen(argv[1], "r");
    if(!fp) {
      perror("Unable to open file at path.\n");
      return EXIT_FAILURE;
    }

    // While the file is being read

    while(fgets(buffer, 1024, fp)){
      //separate the lines of the file into columns
      path = strtok(buffer, ",");
      url = strtok(NULL, "\n");

      open_cert(path, url);
  }

// Close files and exit the program
    fclose(fw);
    fclose(fp);
    exit(0);
}
/*
  Open the certificate to validate
*/
void open_cert(char * path, char * url){
  X509 * cert = NULL;
  BIO * certificate_bio = NULL;
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  // Create BIO object to read certificate
  certificate_bio = BIO_new(BIO_s_file());

  // Read certificate into BIO
  if (!(BIO_read_filename(certificate_bio, path)))
  {
      fprintf(stderr, "Error in reading cert BIO filename\n");
      exit(EXIT_FAILURE);
  }
  if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
  {
      fprintf(stderr, "Error in loading certificate\n");
      exit(EXIT_FAILURE);
  }

  // Run through checks to validate and write to output
  write_to_output(cert, certificate_bio, url, path);

  // Free certificates
  BIO_free_all(certificate_bio);
  X509_free(cert);
}


/*
  If any of the parts of the certificate are invalid, then return as invalid.
  Assuming 0 = false, and 1 = true
*/
int validity(int date, int host, int key_length, int basic_con){
  if(date == 0|| host == 0 || key_length == 0 || basic_con == 0){
    return 0;
  }
  else{
    return 1;
  }
}

/*
  Check the NotBefore and NotAfter date
  Assuming 0 = false, and 1 = true
*/
int check_date(X509 * cert, BIO * c){
  int pday;
  int psec;

  // Documentation found https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_set1_nextUpdate.html
  const ASN1_TIME *before  = X509_get_notBefore(cert);
  const ASN1_TIME *after = X509_get_notAfter(cert);
  /*
    Calculate the time difference between the NotBefore and current date,
    if the difference is positive, then the date has not happened yet
  */
  ASN1_TIME_diff(&pday, &psec, NULL, before);
  if(psec > 0 || pday > 0){
    return 0;
  }
  /*
    Calculate the time difference between the NotAfter and current date
    if difference is negative, then the date has expired
  */
  ASN1_TIME_diff(&pday, &psec, NULL, after);
  if(psec < 0 || pday < 0){
    return 0;
  }
  // The dates are otherwise valid
  else{
    return 1;
  }
}

/*
  Writing the columns as strings to the output.csv file
*/
void output_string(char * path, char * url, int valid){
  char * validity = NULL;
  /*
    Depending on the value of validity, change the output string written
    to file for the Validity column
  */
  if(valid == 0)
  {
    validity = "Invalid";
  }
  if(valid == 1){
    validity = "Valid";
  }

  /*
    Open the file to append, if not able to open to file then error report
  */
  FILE *fw = fopen("output.csv", "a");
  if (!fw) {
      perror("Unable to open output.txt for write\n");
      return;
   }
  else{
    // Print to file
      fprintf(fw, "%s,%s,%d,%s\n", path, url, valid, validity);
   }
   // Close the write file
   fclose(fw);
}

/*
  Matches the url to the CommonName extension, if no SAN is found,
  and also checks for wildcards.
*/
int matches_common_name(char *url, X509 *cert) {
	int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
	char *common_name = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		perror("Unable to find postion of CN field.\n");
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) cert), common_name_loc);
	if (common_name_entry == NULL) {
		perror("No common name found.\n");
	}

	/*
     Convert the CN field to a C string
     Documentation found at: https://www.openssl.org/docs/man1.1.0/crypto/X509_NAME_ENTRY_get_data.html
  */
  common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		perror("Unable to convert to string.\n");
	}
	common_name = (char *) ASN1_STRING_data(common_name_asn1);

  // If the url and common name are the same, is valid
	if (strcasecmp(url, common_name) == 0) {
		return 1;
	}

  /*
    If the url contains the "*" delimiter, then check that the extension of both
    the url and CN are the same.
    e.g www.example.com(url), *.example.com(CN) is valid
    but example.com(url), *.example.com(CN) is not valid as this would require a subdomain
  */
  if(strstr(common_name, "*") != NULL){
    // Find the length of the delimiter, in this case (and usually) "*."
    int delim_len = strlen("*.");
    // The common name without the "*." delimiter
      char* wc = common_name + delim_len;
    // Finding the position of the url within the wildcard
      char* url_ext = strstr(url, wc);
    /*
      If the url doesn't require a subdomain and the extension of the url/wildcard
      are the same then the the common name is valid
    */
      if(strstr(url, "www") != NULL && strcasecmp(url_ext,wc) ==0){
        return 1;
      }
    // Otherwise, invalid
      else{
        return 0;
      }
  }
  else{
    // If invalid then check if there is a match with the Subject Alternative Name
    int san_match_valid = matches_san(url, cert);
		return san_match_valid;
	}
}

/*
  Checks whether the SAN is valid.
*/

int matches_san(char * url, X509 *cert) {
	int i;
  // For match, 1 = valid and 0 = invalid
  int match;
  // The number of SAN
	int san_names_n = -1;
  // Creating an array of SAN, if there are multiple
	char **san_names = NULL;

	/* Extract the names within the SAN extension from the certificate and
     returns a stack of extensions
     Documentation found at: https://www.openssl.org/docs/man1.1.0/crypto/X509_get_ext_d2i.html
  */

	san_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
  // If null there are no SAN
	if (san_names == NULL) {
		return 0;
	}

  // Fill the array with pointers to the SAN
	san_names_n = sk_GENERAL_NAME_num(san_names);

	// Check each name in the array
	for (i=0; i<san_names_n; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
		if (current_name->type == GEN_DNS) {
			// Current name is a DNS name, covert to a string
			char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
			// Compare url with the DNS name
				if (strcasecmp(url, dns_name) == 0) {
					match = 1;
					break;
				}
			}
		}
  // Free the pointers to the memory allocates for the names
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
	return match;
}

/*
  Check the key length of the RSA key in the certificate.
  Assuming that 1 = valid, and 0 = invalid.
*/
int check_key_length(X509 * cert){
  // Number of bits in a byte
  int byte = 8;
  int min_bits = 2048;

  // Get the public and RSA key of the certificate and find the key zie
  EVP_PKEY * public_key = X509_get_pubkey(cert);
  RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
  int key_length = RSA_size(rsa_key);
  //Free the public and RSA key from memory
  EVP_PKEY_free(public_key);
  RSA_free(rsa_key);

  // If the key length is not the minimum number of bits, then invalid
  if((key_length*byte) < min_bits){
    return 0;
  }
  else{
  // Number of bits is valid
    return 1;
  }
}

/*
  Checks the basic constraints and the extended key usage of the certificate.
*/
int check_basic_constraints(X509 * cert){
  /*
    Find the extension and return the buffer retrieved by the 'get_extension()' function call
    for both the basic constraints and key usage.
  */
  X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
  char * bc = get_extension(cert, ex);

  X509_EXTENSION *ex1 = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
  char * ku = get_extension(cert, ex1);
  /*
    If the basic constraints value is false and the key usage contains the below string,
    certificate is valid
  */
  if((strstr(bc, "CA:FALSE") != NULL) && strstr(ku, "TLS Web Server Authentication")){
      return 1;
  }
  else{
  // Certificate is invalid
    return 0;
  }
}

/*
  Get the requested extension for a certificate.
*/
char* get_extension(X509 * cert, X509_EXTENSION *ex){
  //Create an ASN1 object with the extensions
  ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
  char buff[1024];
  //load the object into a buffer
  OBJ_obj2txt(buff, 1024, obj, 0);

  BUF_MEM *bptr = NULL;
  char *buf = NULL;

  BIO *bio = BIO_new(BIO_s_mem());
  if (!X509V3_EXT_print(bio, ex, 0, 0))
  {
      fprintf(stderr, "Error in reading extensions");
  }
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bptr);

  // bptr->data is not NULL terminated - add null character
  buf = (char *)malloc((bptr->length + 1) * sizeof(char));
  memcpy(buf, bptr->data, bptr->length);
  buf[bptr->length] = '\0';

  return buf;
}

/*
  A function to return whether the certificate is valid by running through each
  of the functions.
*/
void write_to_output(X509 * cert, BIO * certificate_bio, char * url, char * path){
  // To validate NotBefore and NotAfter
  int valid_date = check_date(cert, certificate_bio);
  // To validate the host name through SAN and Common Name
  int valid_host_name = matches_common_name(url, cert);
  // To validate the RSA key length
  int valid_key_length = check_key_length(cert);
  // To validate the basic constraints
  int basic_con = check_basic_constraints(cert);
  // To check if all of the above are valid, and if not, returns invalid
  int valid = validity(valid_date, valid_host_name, valid_key_length,basic_con);

  // Output the path to file, the url and validity to the output.csv file
  output_string(path, url, valid);
}
