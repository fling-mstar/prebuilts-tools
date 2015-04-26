make
rm -rf TestFile
mkdir TestFile
mkdir TestFile/encrypted_file
mkdir TestFile/decrypted_file
mkdir TestFile/clear_file

encrypted_path=./TestFile/encrypted_file/
decrypted_path=./TestFile/decrypted_file/
clear_path=./TestFile/clear_file/
secure_storage_file=./programs/aes/

$secure_storage_file/aescrypt2 0 cert.pem $encrypted_path/en_cert.pem efuse_aes_key 0
$secure_storage_file/aescrypt2 0 cert.pem $encrypted_path/en_cert_hmac.pem efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 0 cert.pem $encrypted_path/en_cert_sha.pem efuse_aes_key 2
$secure_storage_file/aescrypt2 0 key.pem $encrypted_path/en_key.pem efuse_aes_key 0
$secure_storage_file/aescrypt2 0 key.pem $encrypted_path/en_key_hmac.pem efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 0 key.pem $encrypted_path/en_key_sha.pem efuse_aes_key 2
$secure_storage_file/aescrypt2 0 test $encrypted_path/output_hmac efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 0 test $encrypted_path/output_sha efuse_aes_key 2
$secure_storage_file/aescrypt2 0 KeyBox.bin $encrypted_path/en_KeyBox.bin efuse_aes_key 0

cp -rf cert.pem $clear_path/cert.pem
cp -rf key.pem $clear_path/key.pem
cp -rf test $clear_path/test
cp -rf KeyBox.bin $clear_path/KeyBox.bin

$secure_storage_file/aescrypt2 1 $encrypted_path/en_cert.pem $decrypted_path/de_cert.pem efuse_aes_key 0
$secure_storage_file/aescrypt2 1 $encrypted_path/en_cert_hmac.pem $decrypted_path/de_cert_hmac.pem efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 1 $encrypted_path/en_cert_sha.pem $decrypted_path/de_cert_sha.pem efuse_aes_key 2
$secure_storage_file/aescrypt2 1 $encrypted_path/en_key.pem $decrypted_path/de_key.pem efuse_aes_key 0
$secure_storage_file/aescrypt2 1 $encrypted_path/en_key_hmac.pem $decrypted_path/de_key_hmac.pem efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 1 $encrypted_path/en_key_sha.pem $decrypted_path/de_key_sha.pem efuse_aes_key 2
$secure_storage_file/aescrypt2 1 $encrypted_path/output_hmac $decrypted_path/de_output_hmac efuse_aes_key 1 Ksh.bin
$secure_storage_file/aescrypt2 1 $encrypted_path/output_sha $decrypted_path/de_output_sha efuse_aes_key 2
$secure_storage_file/aescrypt2 1 $encrypted_path/en_KeyBox.bin $decrypted_path/de_KeyBox.bin efuse_aes_key 0

cmp -b $decrypted_path/de_cert.pem cert.pem
cmp -b $decrypted_path/de_cert_hmac.pem cert.pem
cmp -b $decrypted_path/de_cert_sha.pem cert.pem
cmp -b $decrypted_path/de_key.pem key.pem
cmp -b $decrypted_path/de_key_hmac.pem key.pem
cmp -b $decrypted_path/de_key_sha.pem key.pem
cmp -b $decrypted_path/de_output_sha test
cmp -b $decrypted_path/de_output_hmac test
cmp -b $decrypted_path/de_KeyBox.bin KeyBox.bin

cp -rf $secure_storage_file/aescrypt2 $encrypted_path/aes_padding.exe
cp -rf $encrypted_path/ ./TestFile/ReleaseFile/
cp -rf $clear_path/cert.pem ./TestFile/ReleaseFile/
cp -rf $clear_path/key.pem ./TestFile/ReleaseFile/
cp -rf $clear_path/test ./TestFile/ReleaseFile/
cp -rf $clear_path/KeyBox.bin ./TestFile/ReleaseFile/