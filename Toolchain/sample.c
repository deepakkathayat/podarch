#include "pod_header.h"

#include <stdio.h>
#include <gpg-error.h>

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

gcry_sexp_t sexp_new(const char *str) {
  gcry_error_t error;

  gcry_sexp_t sexp;
  size_t len = strlen(str);
  if ((error = gcry_sexp_new(&sexp, str, len, 1))) {
    printf("Error in sexp_new(%s): %s\nSource: %s\n", str, gcry_strerror(error), gcry_strsource(error));
    exit(1);
  }

  return sexp;
}

char* sexp_string(gcry_sexp_t sexp) {
  size_t buf_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  char *buffer = (char*)gcry_malloc(buf_len);
  if (buffer == NULL) {
    printf("gcry_malloc(%ld) returned NULL in sexp_string()!\n", buf_len);
    exit(1);
  }
  if (0 == gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buffer, buf_len)) {
    printf("gcry_sexp_sprint() lies!\n");
    exit(1);
  }
  return buffer;

  // This should be freed with gcry_free(buffer);
}

void crypto_init(){
  // Version check makes sure that important subsystems are initalized
  if (!gcry_check_version(GCRYPT_VERSION)) {
    printf("libgcrypt version mismatch\n");
    exit(2);
  }

  // Disable secure memory (it's just more hassle I don't think we really need)
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

  // Tell Libgcrypt that initialization has completed.
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void read_key(char **public_key, char **private_key) {

  /* A sample 4096 bit RSA key.  */
  static char sample_secret_key_4096[] =
"(private-key "
" (ecc "
"  (curve Ed25519)"
"  (flags eddsa)"
"  (q #41ED58EA4FC9566FD510F357A426B4C25EB1859877D53CF4C19C43BD01F45A64#)"
"  (d #B60569A2D9E566E39B99208A06BC9FB7B48F4BE1FD4BD0865C2423B6FCBBED39#)"
"  )"
" )";


  /* A sample 4096 bit RSA key (public only).  */
  static char sample_public_key_4096[] =
"(public-key "
" (ecc "
 " (curve Ed25519)"
 " (flags eddsa)"
 " (q #41ED58EA4FC9566FD510F357A426B4C25EB1859877D53CF4C19C43BD01F45A64#)"
 " )"
" )";

  *public_key = sample_public_key_4096;
  *private_key = sample_secret_key_4096;
}

short verify(char *public_key, char *document, char *signature){
	gcry_error_t error;

	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, document, 0, NULL))) {
		printf("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags eddsa) (hash-algo sha512) (value %m))", r_mpi))) {
		printf("Error in gcry_sexp_build() in sign() at %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t sig = sexp_new(signature);

	gcry_sexp_t public_sexp = sexp_new(public_key);
	short good_sig = 1;
	if ((error = gcry_pk_verify(sig, data, public_sexp))) {
		if (gcry_err_code(error) != GPG_ERR_BAD_SIGNATURE) {
			printf("Error in gcry_pk_verify(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
			exit(1);
		}
		good_sig = 0;
	}
	return good_sig;
}

int main() {
    pod_init();

	crypto_init();

	char *public_key, *private_key;

	read_key(&public_key, &private_key);
	//printf("Public Key:\n%s\n\n", public_key);
	//printf("Private Key:\n%s\n\n", private_key);

	char *plaintext = "DEADBEEF1234567890";
	//printf("Plain Text:\n%s\n\n", plaintext);

	static char signature[] = 
"(sig-val "
" (eddsa "
"  (r #7506BAB8325A7529B3DF5A6327F75CF7A122198AF9894BD89030DB45294AB9AD#)"
 " (s #0DE926EBA877D0084886495D0C62D1F2AF286781B49FCB678F412FC4580A550F#)"
 " )"
" )";


	//printf("Signature:\n%s\n\n", signature);

	//printf("Verification:\n");
	if (verify(public_key, plaintext, signature)) {
		printf("MY Signature GOOD!\n");
	} else {
		printf("Signature BAD!\n");
	}

}
