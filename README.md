# paycorp-security

[![CodeQL](https://github.com/prashantevolvus/paycorp-security/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/prashantevolvus/paycorp-security/actions/workflows/codeql-analysis.yml)

## Introduction
This is used to encrypt, decrypt, sign xml and verify xml. 

## Usage

```
usage: security.sh
 -d,--decrypt            Decrypt the input file
 -e,--encrypt            Encrypt the input file
 -h,--help               Help on this tool usage
 -i,--inputFile <arg>    Input File
 -o,--outputFile <arg>   Output File
 -s,--sign               Sign the XML File
 -v,--verify             Verify the signature of XML File
```
 ## To Do
 1. Key management must be configurable
 2. JKS store must be more friendly
