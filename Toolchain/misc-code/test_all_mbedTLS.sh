#!/usr/bin/env bash
#
# ./test_all_mbedTLS.sh [vanilla|podarch]
#
# An utility script to check all mbedTLS binaries
# Please call this along with input test files
#
# Author: Viswesh Narayanan (visweshn92)

if [[ ( "$#" -ne 0 ) && ( "$1" = "vanilla" ) ]]; then

    vanilla_list="test_suite_aes.cbc test_suite_aes.cfb test_suite_aes.ecb test_suite_aes.rest test_suite_arc4 test_suite_asn1write test_suite_base64 test_suite_blowfish test_suite_camellia test_suite_ccm test_suite_cipher.aes test_suite_cipher.arc4 test_suite_cipher.blowfish test_suite_cipher.camellia test_suite_cipher.ccm test_suite_cipher.des test_suite_cipher.gcm test_suite_cipher.null test_suite_cipher.padding test_suite_debug test_suite_des test_suite_dhm test_suite_ecdh test_suite_ecdsa test_suite_ecp test_suite_entropy test_suite_error test_suite_gcm.aes128_de test_suite_gcm.aes128_en test_suite_gcm.aes192_de test_suite_gcm.aes192_en test_suite_gcm.aes256_de test_suite_gcm.aes256_en test_suite_gcm.camellia test_suite_hmac_drbg.misc test_suite_hmac_drbg.nopr test_suite_hmac_drbg.no_reseed test_suite_hmac_drbg.pr test_suite_hmac_shax test_suite_md test_suite_mdx test_suite_memory_buffer_alloc test_suite_mpi test_suite_pbkdf2 test_suite_pem test_suite_pk test_suite_pkcs1_v21 test_suite_pkcs5 test_suite_pkparse test_suite_pkwrite test_suite_rsa test_suite_shax test_suite_version test_suite_x509parse test_suite_x509write test_suite_xtea test_suite_ctr_drbg"

    for bin in $vanilla_list
    do
        ./$bin > /tmp/1 2> /tmp/2
        rc=$? 
        if [ $rc != 0 ] 
        then 
            echo "Failed: $bin"
            exit $rc 
        fi
    done

    echo "Vanilla - All Passed!"
fi

if [[ ( "$#" -ne 0 ) && ( "$1" = "podarch" ) ]]; then

    pod_list="test_suite_aes.cbc_pod test_suite_aes.cfb_pod test_suite_aes.ecb_pod test_suite_aes.rest_pod test_suite_arc4_pod test_suite_asn1write_pod test_suite_base64_pod test_suite_blowfish_pod test_suite_camellia_pod test_suite_ccm_pod test_suite_cipher.aes_pod test_suite_cipher.arc4_pod test_suite_cipher.blowfish_pod test_suite_cipher.camellia_pod test_suite_cipher.ccm_pod test_suite_cipher.des_pod test_suite_cipher.gcm_pod test_suite_cipher.null_pod test_suite_cipher.padding_pod test_suite_debug_pod test_suite_des_pod test_suite_dhm_pod test_suite_ecdh_pod test_suite_ecdsa_pod test_suite_ecp_pod test_suite_entropy_pod test_suite_error_pod test_suite_gcm.aes128_de_pod test_suite_gcm.aes128_en_pod test_suite_gcm.aes192_de_pod test_suite_gcm.aes192_en_pod test_suite_gcm.aes256_de_pod test_suite_gcm.aes256_en_pod test_suite_gcm.camellia_pod test_suite_hmac_drbg.misc_pod test_suite_hmac_drbg.nopr_pod test_suite_hmac_drbg.no_reseed_pod test_suite_hmac_drbg.pr_pod test_suite_hmac_shax_pod test_suite_md_pod test_suite_mdx_pod test_suite_memory_buffer_alloc_pod test_suite_mpi_pod test_suite_pbkdf2_pod test_suite_pem_pod test_suite_pk_pod test_suite_pkcs1_v21_pod test_suite_pkcs5_pod test_suite_pkparse_pod test_suite_pkwrite_pod test_suite_rsa_pod test_suite_shax_pod test_suite_version_pod test_suite_x509parse_pod test_suite_x509write_pod test_suite_xtea_pod test_suite_ctr_drbg_pod"

    for bin in $pod_list
    do
        ./$bin > /tmp/1 2> /tmp/2
        rc=$?
        if [ $rc != 0 ]
        then
            echo "Failed: $bin"
            exit $rc
        fi
    done

    echo "PodArch - All Passed!"
fi

exit 0
