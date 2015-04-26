Read Me:
    "\n  For CI+ Credentials: secure <mode> <device cert filename> <keys cert filename> <serial no> <ci+.bin filename> \n" \
    "\n  <mode>: 0 = Create ci+.bin, 1 = Verify ci+.bin\n" \
    "\n  example: ./secure 0 device.der keys.der 3 ci+.bin\n" \
    "\n  example: ./secure 1 ci+.bin\n" \
    "\n  For CANAL READY Auth Certificate: secure <mode> <canal ready auth cert filename> <canal_ready_auth.bin filename> \n" \
    "\n  <mode>: 2 = Create canal_ready_auth.bin, 3 = Verify canal_ready_auth.bin\n" \
    "\n  example: ./secure 2 TNT_XXX_BETA7.bin canal_ready_auth.bin\n" \
    "\n  example: ./secure 3 canal_ready_auth.bin\n" \
    "\n"

NOTE: For CI+ Credentials Bin, we suggest that use DER format of all certificates.
	If your certificates are PEM format, please use openssl to covert to DER format.
	EX: 
	  openssl x509 -outform der -in ciplus_test_ca.crt -out ciplus_test_ca.der

Example:
<CI+ Credentials Bin>
  <Test Keys>
  ./secure 0 ciplus_test_root.der ciplus_test_ca.der 1F189791A1B3CAF1-cert.der 1F189791A1B3CAF1-key.der 1239 ci+_test.bin
  ./secure 1 ci+_test.bin

  <Production Keys>
  ./secure 0 ciplus_root.der cert.der 0A0BE5329B9C6E95-cert.der 0A0BE5329B9C6E95-key.der 1239 ci+_prod.bin
  ./secure 1 ci+_test.bin


<CANAL READY Auth Certificate Bin>
  ./secure 2 TNT_XXX_BETA7.bin canal_ready_auth.bin
  ./secure 3 canal_ready_auth.bin
