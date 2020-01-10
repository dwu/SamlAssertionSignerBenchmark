## Run benchmarks

```
$ mvn clean install
$ java -jar target/benchmarks.jar
```

## Notes

Keys were generated via keytool:

```
$ keytool -genkey -keyalg RSA -alias test2048 -keystore keystore.jks -storepass password -validity 360 -keysize 2048
$ keytool -genkey -keyalg RSA -alias test4096 -keystore keystore.jks -storepass password -validity 360 -keysize 4096
$ keytool -genkey -keyalg RSA -alias test8192 -keystore keystore.jks -storepass password -validity 360 -keysize 8192
```
