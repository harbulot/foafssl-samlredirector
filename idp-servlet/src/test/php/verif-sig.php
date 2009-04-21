<?php


$url_encoded_signature="u%2FSrRoFQR6GAJsOrog09eRFhgopE4AsrnVGmrqNabAOOVfeu5ThEarEUm%2BrJBDE1i1cxiLFUJy1tV%2F8hE6vgzfHv2JVKg9gyF%2FslCYj7fvfVnbR4ho5nziUxlV7%2FGaNapIO6lmCTaeOevRU%2BOVJX4q0rCXtsjysRuwgEXuzTERc%3D";

$good_reply = "http://sp.example.com/sp/?FoafSslAuthnUri=http%3A%2F%2Ffoaf.example.net%2Fbruno%23me&FoafSslAuthnDateTime=2009-04-21T23%3A48%3A57%2B0100&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1";
$bad_reply = "http://sp.example.com/sp/?FoafSslAuthnUri=http%3A%2F%2Ffoaf.example.net%2Fbruno%23notme&FoafSslAuthnDateTime=2009-04-21T23%3A48%3A57%2B0100&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1";


$signature = base64_decode(urldecode($url_encoded_signature));

$fp = fopen("../resources/localhost-cert.pem", "r");
$cert = fread($fp, 8192);
fclose($fp);

/*
 * It seems to work eiher with the cert or the key.
 */
$pubkeyid = openssl_get_publickey($cert);

$verified = openssl_verify($good_reply, $signature, $pubkeyid);
if ($verified == 1) {
	echo "PASS: verifying good reply.\n";
} elseif ($verified == 0) {
	echo "FAIL: verifying good reply.\n";
} else {
	echo "ERROR: verifying good reply.\n";
}

$verified = openssl_verify($bad_reply, $signature, $pubkeyid);
if ($verified == 1) {
	echo "FAIL: verifying bad reply.\n";
} elseif ($verified == 0) {
	echo "PASS: verifying bad reply.\n";
} else {
	echo "ERROR: verifying bad reply.\n";
}

openssl_free_key($pubkeyid);

?>