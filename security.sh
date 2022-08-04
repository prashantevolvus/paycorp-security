export CLASSPATH=paycorp-security-1.0-SNAPSHOT.jar:commons-cli-1.4.jar:slf4j-api-1.7.32.jar:logback-classic-1.2.5.jar:logback-core-1.2.5.jar

export TWADKEY="b5ff6db1e2f1d27d294047b220516312da1b4ba899035692e893e16815fc9784"
export KS_FILE="keys/indianbank.jks"
export KS_PASS="serbia"
export KS_ALIAS="54eb870d9ad14386a54e3743ccadd88a"

export KS_CLIENT_ALIAS="TNWBD"


java com.paycorp.security.App $1 $2 $3 $4 $5 $6 $7 $8

