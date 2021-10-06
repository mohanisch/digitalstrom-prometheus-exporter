# digitalstrom-prometheus-exporter

The exporter currently collects from the dSS the power consumption and status of individual devices.

```
# HELP dss_appartment_consumption Current total power consumption [W]
# TYPE dss_appartment_consumption gauge
dss_appartment_consumption 11.0

# HELP dss_circuit_consumption Current power consumption [W]
# TYPE dss_circuit_consumption gauge
dss_circuit_consumption{circuit="circuit livingroom",hwName="dSM12"} 7.0

# HELP dss_circuit_metervalue Current measurent of the power consumption [Ws]
# TYPE dss_circuit_metervalue gauge
dss_circuit_metervalue{circuit="circuit livingroom",hwName="dSM12"} 1.5145362e+07

# HELP dss_device_is_present Current state of device
# TYPE dss_device_is_present gauge
dss_device_is_present{device="livingroom_ceiling_lamp ",hwName="dSM12"} 1.0
```

### Preparation
#### Obtaining appToken
To enable a new application you have to create a token in your DSS. Change the password for `dssadmin_pasword` in the following command and run them.
At the end you will get the application token to use for thhis exporter
```
dssadmin_password=PasswOrD
applicationToken=$(curl -sk https://dss.local:8080/json/system/requestApplicationToken?applicationName=prometheus_exporter | jq .result.applicationToken)
logintoken=$(curl -sk https://dss.local:8080/json/system/login?user=dssadmin\&password=${dssadmin_password} | jq .result.token) 
curl -sk \
  --header "Cookie: token=${logintoken}" \
https://dss.local:8080/json/system/enableToken?applicationToken=${applicationToken} | jq .
echo ${applicationToken}
```

### Usage
Run the container and adjust `DSS_HOST` and `DSS_LOGINTOKEN` with the given values.
```
docker run -d \
    --restart always \
    -p 9184:9184 \
    -e DSS_HOST=https://dss.local \
    -e DSS_LOGINTOKEN=4fa07386c77d7f32260066c83b58aece5814698376bd03f0e3b5764e58f0ec1a \
    marcohanisch/digitalstrom-prometheus-exporter
```

#Changelog
v1.0.3

