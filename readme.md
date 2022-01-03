# GrootCA

## About
Simple Go cli-tool to create a CA and issue TLS Certificates for hostnames. Initial plan was just to deploy certs for
services in local LAN. Played with bahs and openssl, ended implementing it in GO. Typical weekend pet project gone wild.
Learned a lot about x509 and RSA/EC Keys. Read more about it [here](https://blog.habales.de/)  

## Usage
- Create a CA (Keys and Certificate)
- Create Keys and issue TLS Certificates for Hostnames 

### Create a CA

    ./GrootCA init-ca -k <key_type> path

Where key_type is either _RSA_, _ECDSA_ or _Ed25519_. Default is RSA

### Issue Certfocate

    ./GrootCA issue harbor,harbor.local

### Reference

XXXXXXX

## Todo
- [ ] Randomized Serials 
- [ ] Sanity check input for hostnames. At least trim(), better validate fully 